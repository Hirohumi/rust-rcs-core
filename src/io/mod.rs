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

use std::io::Read;

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
