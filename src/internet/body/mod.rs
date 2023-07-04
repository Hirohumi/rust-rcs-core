// Copyright 2023 宋昊文
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

pub mod message_body;
pub mod multipart_body;
pub mod streamed_body;

use std::{
    fmt,
    fs::File,
    io::{Read, Seek},
    pin::Pin,
    task::{Context, Poll},
};

use crate::io::{DynamicChain, Serializable};

use futures::AsyncRead;
use message_body::MessageBody;
use multipart_body::MultipartBody;
use streamed_body::StreamedBody;

use self::streamed_body::StreamSource;

#[derive(Debug)]
pub enum BodySerializationError {
    IO,
}

pub enum Body {
    Raw(Vec<u8>),
    Message(MessageBody),
    Multipart(MultipartBody),
    Streamed(StreamedBody),
}

impl Serializable for Body {
    // fn serialize(&self) -> Vec<u8> {
    //     match self {
    //         Body::Raw(data) => data.clone(),
    //         Body::Message(message) => message.serialize(),
    //         Body::Multipart(multipart) => multipart.serialize(),
    //     }
    // }

    fn estimated_size(&self) -> usize {
        match self {
            Body::Raw(data) => data.len(),
            Body::Message(message) => message.estimated_size(),
            Body::Multipart(multipart) => multipart.estimated_size(),
            Body::Streamed(stream) => stream.stream_size,
        }
    }
}

impl Body {
    pub fn construct_raw(data: &[u8]) -> Body {
        Body::Raw(data.to_vec())
    }

    pub fn construct_message(data: &[u8]) -> Result<Body, &'static str> {
        Ok(Body::Message(MessageBody::construct(data)?))
    }

    pub fn construct_multipart(data: &[u8], boundary: &[u8]) -> Result<Body, &'static str> {
        Ok(Body::Multipart(MultipartBody::construct(data, boundary)?))
    }

    pub fn reader(&self) -> Result<BodyReader, BodySerializationError> {
        match self {
            Body::Raw(data) => Ok(BodyReader::Raw(RawBodyReader { data, pos: 0 })),
            Body::Message(message) => {
                let mut readers = Vec::new();
                message.get_readers(&mut readers)?;
                let chain = DynamicChain::new(readers);
                Ok(BodyReader::Message(chain))
            }
            Body::Multipart(multipart) => {
                let mut readers = Vec::new();
                multipart.get_readers(&mut readers)?;
                let chain = DynamicChain::new(readers);
                Ok(BodyReader::Multipart(chain))
            }
            Body::Streamed(stream) => match &stream.stream_source {
                StreamSource::File((path, skip)) => {
                    if let Ok(mut f) = File::open(path) {
                        if *skip != 0 {
                            if let Ok(skip) = (*skip).try_into() {
                                if let Ok(skipped) = f.seek(std::io::SeekFrom::Start(skip)) {
                                    if skipped == skip {
                                        return Ok(BodyReader::FileBacked(f));
                                    }
                                }
                            }

                            return Err(BodySerializationError::IO);
                        }

                        return Ok(BodyReader::FileBacked(f));
                    }

                    Err(BodySerializationError::IO)
                }
            },
        }
    }
}

// impl Clone for Body {
//     fn clone(&self) -> Self {
//         match self {
//             Body::Raw(inner) => Body::Raw(inner.clone()),
//             Body::Message(inner) => Body::Message(inner.clone()),
//             Body::Multipart(inner) => Body::Multipart(inner.clone()),
//             Body::Streamed(inner) => panic!(""),
//         }
//     }
// }

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Body::Raw(data) => {
                write!(f, "Raw [u8; {}]", data.len())
            }
            Body::Message(message) => {
                write!(f, "{:?}", message)
            }
            Body::Multipart(multipart) => {
                write!(f, "{:?}", multipart)
            }
            Body::Streamed(stream) => {
                write!(f, "Streamd [u8; {}]", stream.stream_size)
            }
        }
    }
}

pub enum BodyReader<'a> {
    Raw(RawBodyReader<'a>),
    Message(DynamicChain<'a>),
    Multipart(DynamicChain<'a>),
    FileBacked(File),
}

impl Read for BodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            BodyReader::Raw(reader) => reader.read(buf),
            BodyReader::Message(reader) => reader.read(buf),
            BodyReader::Multipart(reader) => reader.read(buf),
            BodyReader::FileBacked(f) => f.read(buf),
        }
    }
}

impl AsyncRead for BodyReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = self.get_mut();
        match r {
            BodyReader::Raw(reader) => Pin::new(reader).poll_read(cx, buf),
            BodyReader::Message(reader) => Pin::new(reader).poll_read(cx, buf),
            BodyReader::Multipart(reader) => Pin::new(reader).poll_read(cx, buf),
            BodyReader::FileBacked(f) => Poll::Ready(f.read(buf)),
        }
    }
}

pub struct RawBodyReader<'a> {
    data: &'a Vec<u8>,
    pos: usize,
}

impl Read for RawBodyReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < self.data.len() && i < buf.len() {
            buf[i] = self.data[self.pos + i];
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}

impl AsyncRead for RawBodyReader<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = self.get_mut();
        Poll::Ready(r.read(buf))
    }
}

pub struct VectorReader {
    data: Vec<u8>,
    pos: usize,
}

impl VectorReader {
    pub fn new(data: Vec<u8>) -> VectorReader {
        VectorReader { data, pos: 0 }
    }
}

impl Read for VectorReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < self.data.len() && i < buf.len() {
            buf[i] = self.data[self.pos + i];
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}

impl AsyncRead for VectorReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = self.get_mut();
        Poll::Ready(r.read(buf))
    }
}
