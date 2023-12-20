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

extern crate futures;
extern crate httparse;
extern crate tokio;

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::Future;

use httparse::{Response as ResponseParser, Status};

use tokio::io::{AsyncRead, ReadBuf, ReadHalf};

use crate::ffi::log::platform_log;

use crate::io::network::stream::ClientStream;

use super::response::Response;

const LOG_TAG: &str = "http_decode";

pub enum HeaderPartDecodeStatus {
    Success(Response),
    Again,
    BufferTooSmall,
    EOF,
}

pub struct HeaderPartDecoder<'a, 'b> {
    buf: &'a mut ReadBuf<'b>,
    consumed: &'a mut usize,
    rh: &'a mut ReadHalf<ClientStream>,
}

impl<'a, 'b> HeaderPartDecoder<'a, 'b> {
    pub fn new(
        buf: &'a mut ReadBuf<'b>,
        consumed: &'a mut usize,
        rh: &'a mut ReadHalf<ClientStream>,
    ) -> HeaderPartDecoder<'a, 'b> {
        HeaderPartDecoder { buf, consumed, rh }
    }
}

impl Future for HeaderPartDecoder<'_, '_> {
    type Output = Result<HeaderPartDecodeStatus>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "HeaderPartDecoder poll()");

        let decoder = self.get_mut();
        if decoder.buf.filled().len() == *decoder.consumed && *decoder.consumed != 0 {
            platform_log(LOG_TAG, "making space for poll_read");
            decoder.buf.clear();
            *decoder.consumed = 0;
        }

        let before_read = decoder.buf.filled().len();

        match Pin::new(&mut decoder.rh).poll_read(cx, &mut decoder.buf) {
            Poll::Ready(Ok(())) => {
                platform_log(
                    LOG_TAG,
                    format!(
                        "poll_read success with new data range {}-{}",
                        *decoder.consumed,
                        decoder.buf.filled().len()
                    ),
                );

                let after_read = decoder.buf.filled().len();

                let pending_data = &decoder.buf.filled()[*decoder.consumed..];
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut parser = ResponseParser::new(&mut headers);
                if let Ok(status) = parser.parse(pending_data) {
                    match status {
                        Status::Partial => {
                            platform_log(LOG_TAG, "on partial http header");

                            if before_read == after_read {
                                platform_log(LOG_TAG, "no more data");
                                return Poll::Ready(Ok(HeaderPartDecodeStatus::EOF));
                            }

                            if decoder.buf.remaining() > 0 {
                                Poll::Ready(Ok(HeaderPartDecodeStatus::Again))
                            } else {
                                Poll::Ready(Ok(HeaderPartDecodeStatus::BufferTooSmall))
                            }
                        }

                        Status::Complete(size) => {
                            platform_log(LOG_TAG, "on complete http header");
                            if let Some(resp) = Response::from(&parser) {
                                *decoder.consumed += size;

                                Poll::Ready(Ok(HeaderPartDecodeStatus::Success(resp)))
                            } else {
                                Poll::Ready(Err(ErrorKind::Parse))
                            }
                        }
                    }
                } else {
                    Poll::Ready(Err(ErrorKind::Parse))
                }
            }

            Poll::Ready(Err(e)) => Poll::Ready(Err(ErrorKind::Io(e))),

            Poll::Pending => Poll::Pending,
        }
    }
}

pub enum ChunkDecodeResult {
    Part(Vec<u8>),
    Again,
    BufferTooSmall,
    EOF,
}

pub struct ChunkDecoder<'a, 'b> {
    buf: &'a mut ReadBuf<'b>,
    consumed: &'a mut usize,
    rh: &'a mut ReadHalf<ClientStream>,
}

impl<'a, 'b> ChunkDecoder<'a, 'b> {
    pub fn new(
        buf: &'a mut ReadBuf<'b>,
        consumed: &'a mut usize,
        rh: &'a mut ReadHalf<ClientStream>,
    ) -> ChunkDecoder<'a, 'b> {
        ChunkDecoder { buf, consumed, rh }
    }
}

impl Future for ChunkDecoder<'_, '_> {
    type Output = Result<ChunkDecodeResult>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "ChunkDecoder poll()");

        let decoder: &mut ChunkDecoder<'_, '_> = self.get_mut();
        if decoder.buf.filled().len() == *decoder.consumed && *decoder.consumed != 0 {
            platform_log(LOG_TAG, "making space for poll_read");
            decoder.buf.clear();
            *decoder.consumed = 0;
        }

        let pending_data = &decoder.buf.filled()[*decoder.consumed..];

        match httparse::parse_chunk_size(pending_data) {
            Ok(status) => match status {
                Status::Complete((index, size)) => {
                    platform_log(LOG_TAG, format!("on complete chunk of size {}", size));

                    if size == 0 {
                        *decoder.consumed += index;
                        *decoder.consumed += 2;

                        Poll::Ready(Ok(ChunkDecodeResult::EOF))
                    } else {
                        if let Ok(size) = size.try_into() {
                            let pending_data = &decoder.buf.filled()[*decoder.consumed + index..];

                            platform_log(
                                LOG_TAG,
                                format!("data currently available is {} bytes", pending_data.len()),
                            );

                            if pending_data.len() >= size {
                                let data = pending_data[..size].to_vec();

                                *decoder.consumed += index;
                                *decoder.consumed += data.len();
                                *decoder.consumed += 2;

                                Poll::Ready(Ok(ChunkDecodeResult::Part(data)))
                            } else {
                                if decoder.buf.remaining() == 0 {
                                    Poll::Ready(Ok(ChunkDecodeResult::BufferTooSmall))
                                } else {
                                    let before_read = decoder.buf.filled().len();

                                    match Pin::new(&mut decoder.rh).poll_read(cx, &mut decoder.buf)
                                    {
                                        Poll::Ready(Ok(())) => {
                                            platform_log(
                                                LOG_TAG,
                                                format!(
                                                    "poll_read success with new data range {}-{}",
                                                    *decoder.consumed,
                                                    decoder.buf.filled().len()
                                                ),
                                            );

                                            let after_read = decoder.buf.filled().len();

                                            if before_read == after_read {
                                                platform_log(LOG_TAG, "no more data");
                                                Poll::Ready(Ok(ChunkDecodeResult::EOF))
                                            } else {
                                                Poll::Ready(Ok(ChunkDecodeResult::Again))
                                            }
                                        }

                                        Poll::Ready(Err(e)) => Poll::Ready(Err(ErrorKind::Io(e))),

                                        Poll::Pending => Poll::Pending,
                                    }
                                }
                            }
                        } else {
                            Poll::Ready(Err(ErrorKind::Parse))
                        }
                    }
                }

                Status::Partial => {
                    platform_log(LOG_TAG, "on partial chunk");

                    if decoder.buf.remaining() == 0 {
                        Poll::Ready(Ok(ChunkDecodeResult::BufferTooSmall))
                    } else {
                        let before_read = decoder.buf.filled().len();

                        match Pin::new(&mut decoder.rh).poll_read(cx, &mut decoder.buf) {
                            Poll::Ready(Ok(())) => {
                                platform_log(
                                    LOG_TAG,
                                    format!(
                                        "poll_read success with new data range {}-{}",
                                        *decoder.consumed,
                                        decoder.buf.filled().len()
                                    ),
                                );

                                let after_read = decoder.buf.filled().len();

                                if before_read == after_read {
                                    platform_log(LOG_TAG, "no more data");
                                    Poll::Ready(Ok(ChunkDecodeResult::EOF))
                                } else {
                                    Poll::Ready(Ok(ChunkDecodeResult::Again))
                                }
                            }

                            Poll::Ready(Err(e)) => Poll::Ready(Err(ErrorKind::Io(e))),

                            Poll::Pending => Poll::Pending,
                        }
                    }
                }
            },

            Err(_) => Poll::Ready(Err(ErrorKind::Parse)),
        }
    }
}

pub enum ErrorKind {
    Io(io::Error),
    Parse,
}

impl Clone for ErrorKind {
    fn clone(&self) -> ErrorKind {
        match self {
            ErrorKind::Io(e) => ErrorKind::Io(io::Error::from(e.kind())),

            ErrorKind::Parse => ErrorKind::Parse,
        }
    }
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => {
                write!(f, "Io error {:?}", e)
            }

            ErrorKind::Parse => {
                write!(f, "Parse")
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorKind>;
