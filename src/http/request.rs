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

extern crate url;

use std::io::Read;
use std::str;

use crate::internet::Body;
use crate::io::{BytesReader, Serializable};

use crate::internet::header::{headers_get_readers, Header};

pub const GET: &[u8] = b"GET";
pub const POST: &[u8] = b"POST";
pub const PUT: &[u8] = b"PUT";
pub const DELETE: &[u8] = b"DELETE";
pub const HEAD: &[u8] = b"HEAD";
pub const CONNECT: &[u8] = b"CONNECT";

pub struct Request {
    pub method: &'static [u8],
    pub reference: String,
    pub headers: Vec<Header>,
    pub body: Option<Body>,
}

impl Request {
    pub fn new_with_default_headers(
        method: &'static [u8],
        host: &str,
        path: &str,
        query: Option<&str>,
    ) -> Request {
        let mut headers = Vec::new();

        headers.push(Header::new(b"Host", String::from(host)));

        headers.push(Header::new(b"Accept", "*/*"));

        headers.push(Header::new(b"Cache-Control", "no-cache"));

        headers.push(Header::new(b"User-Agent", "CPM-client/OMA2.2 RCS-client/UP_2.4 term-Hisense/HNR550T-9 client-Rusty/1.0.0 OS-Android/9 Channel-terminal-000000 Channel-client-000000 3gpp-gba"));

        if let Some(query) = query {
            Request {
                method,
                reference: format!("{}?{}", path, query),
                headers,
                body: None,
            }
        } else {
            Request {
                method,
                reference: String::from(path),
                headers,
                body: None,
            }
        }
    }

    pub fn get_readers<'a>(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        readers.push(Box::new(BytesReader::new(self.method)));
        readers.push(Box::new(BytesReader::new(b" ")));
        readers.push(Box::new(self.reference.as_bytes()));
        readers.push(Box::new(&b" HTTP/1.1\r\n"[..]));

        headers_get_readers(&self.headers, readers);

        readers.push(Box::new(&b"\r\n"[..]));
    }
}

impl Serializable for Request {
    fn estimated_size(&self) -> usize {
        let mut size = 0;

        size += self.method.len();
        size += 1;
        size += self.reference.as_bytes().len();
        size += 11;

        size += self.headers.estimated_size();

        size += 2;

        size
    }
}
