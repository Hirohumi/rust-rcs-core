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

use std::fmt;
use std::io::Read;
use std::slice::Iter;

use crate::io::Serializable;

pub struct Header {
    name: Box<dyn AsRef<[u8]> + Send + Sync>,
    value: Box<dyn AsRef<[u8]> + Send + Sync>,
}

impl Header {
    pub fn new<N, V>(name: N, value: V) -> Header
    where
        N: AsRef<[u8]> + Send + Sync + 'static,
        V: AsRef<[u8]> + Send + Sync + 'static,
    {
        Header {
            name: Box::new(name),
            value: Box::new(value),
        }
    }

    pub fn get_name(&self) -> &[u8] {
        self.name.as_ref().as_ref()
    }

    pub fn get_value(&self) -> &[u8] {
        self.value.as_ref().as_ref()
    }

    pub fn reader(&self) -> HeaderReader {
        HeaderReader {
            header: self,
            pos: 0,
        }
    }
}

impl Clone for Header {
    fn clone(&self) -> Self {
        Header {
            name: Box::new(self.name.as_ref().as_ref().to_vec()),
            value: Box::new(self.value.as_ref().as_ref().to_vec()),
        }
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Header")
            .field(
                &String::from_utf8_lossy(self.name.as_ref().as_ref()),
                &String::from_utf8_lossy(self.value.as_ref().as_ref()),
            )
            .finish()
    }
}

pub struct HeaderReader<'a> {
    header: &'a Header,
    pos: usize,
}

impl<'a> Read for HeaderReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let name = self.header.name.as_ref().as_ref();
        let value = self.header.value.as_ref().as_ref();
        let mut i = 0;
        while self.pos + i < name.len() && i < buf.len() {
            buf[i] = name[self.pos + i];
            i += 1;
        }
        while self.pos + i >= name.len() && self.pos + i < name.len() + 2 && i < buf.len() {
            if self.pos + i == name.len() {
                buf[i] = b':';
            } else {
                buf[i] = b' ';
            }
            i += 1;
        }
        while self.pos + i >= name.len() + 2
            && self.pos + i < name.len() + 2 + value.len()
            && i < buf.len()
        {
            buf[i] = value[self.pos + i - name.len() - 2];
            i += 1;
        }
        while self.pos + i >= name.len() + 2 + value.len()
            && self.pos + i < name.len() + 2 + value.len() + 2
            && i < buf.len()
        {
            if self.pos + i == name.len() + 2 + value.len() {
                buf[i] = b'\r';
            } else {
                buf[i] = b'\n';
            }
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}

pub struct HeaderSearch<'a, 'b> {
    iter: Iter<'a, Header>,
    name: &'b [u8],
    ignore_case: bool,
}

impl<'a, 'b> HeaderSearch<'a, 'b> {
    pub fn new(headers: &'a [Header], name: &'b [u8], ignore_case: bool) -> HeaderSearch<'a, 'b> {
        HeaderSearch {
            iter: headers.iter(),
            name,
            ignore_case,
        }
    }
}

impl<'a, 'b> Iterator for HeaderSearch<'a, '_> {
    type Item = &'a Header;
    fn next(&mut self) -> Option<&'a Header> {
        while let Some(h) = self.iter.next() {
            if self.ignore_case {
                if h.name.as_ref().as_ref().eq_ignore_ascii_case(self.name) {
                    return Some(h);
                }
            } else {
                if h.name.as_ref().as_ref().eq(self.name) {
                    return Some(h);
                }
            }
        }

        None
    }
}

pub fn search<'a>(headers: &'a [Header], name: &[u8], ignore_case: bool) -> Option<&'a Header> {
    HeaderSearch::new(headers, name, ignore_case).next()
}

impl Serializable for [Header] {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::new();
    //     for header in self {
    //         data.extend_from_slice(header.name.as_ref().as_ref());
    //         data.extend(b": ");
    //         data.extend_from_slice(header.value.as_ref().as_ref());
    //         data.extend(b"\r\n");
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        for header in self {
            size += header.name.as_ref().as_ref().len();
            size += 2;
            size += header.value.as_ref().as_ref().len();
            size += 2;
        }
        size
    }
}

pub fn headers_get_readers<'a>(
    headers: &'a [Header],
    readers: &mut Vec<Box<dyn Read + Send + 'a>>,
) {
    for header in headers {
        readers.push(Box::new(header.reader()));
    }
}
