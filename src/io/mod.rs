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

pub mod async_io;
pub mod network;

use std::{io::Read, pin::Pin, task::Poll};

use futures::AsyncRead;

pub trait Serializable {
    fn estimated_size(&self) -> usize;
}

pub struct BytesReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BytesReader<'_> {
    pub fn new<'a>(data: &'a [u8]) -> BytesReader<'a> {
        BytesReader { data, pos: 0 }
    }
}

impl Read for BytesReader<'_> {
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

pub struct DynamicChain<'a> {
    readers: Vec<Box<dyn Read + Send + 'a>>,
}

impl<'a> DynamicChain<'a> {
    pub fn new(readers: Vec<Box<dyn Read + Send + 'a>>) -> DynamicChain<'a> {
        DynamicChain { readers }
    }

    pub fn push<'b, T>(&'a mut self, reader: T)
    where
        T: Read + Send + 'b,
        'b: 'a,
    {
        self.readers.push(Box::new(reader));
    }
}

impl Read for DynamicChain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        for reader in &mut self.readers {
            loop {
                let r = reader.read(&mut buf[i..])?;
                i += r;
                if r == 0 {
                    break;
                }
            }
            if i >= buf.len() {
                break;
            }
        }
        Ok(i)
    }
}

pub struct ProgressReportingReader<T> {
    inner: T,
    read: usize,
    callback: Box<dyn Fn(usize) + Send + Sync>,
}

impl<T> ProgressReportingReader<T> {
    pub fn new<C>(reader: T, callback: C) -> ProgressReportingReader<T>
    where
        C: Fn(usize) + Send + Sync + 'static,
    {
        ProgressReportingReader {
            inner: reader,
            read: 0,
            callback: Box::new(callback),
        }
    }
}

impl<T> AsyncRead for ProgressReportingReader<T>
where
    T: AsyncRead + Send + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = self.get_mut();
        match Pin::new(&mut r.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(size)) => {
                r.read += size;
                (r.callback)(r.read);
                Poll::Ready(Ok(size))
            }

            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),

            Poll::Pending => Poll::Pending,
        }
    }
}
