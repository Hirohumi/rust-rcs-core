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

use std::io::Read;
use std::sync::Arc;

use crate::io::Serializable;
use crate::util::raw_string::StrFind;

use super::super::syntax;
use super::{Body, BodySerializationError};

#[derive(Debug)]
pub struct MultipartBody {
    pub boundary: Vec<u8>,
    pub parts: Vec<Arc<Body>>,
}

impl MultipartBody {
    pub fn construct(data: &[u8], boundary: &[u8]) -> Result<MultipartBody, &'static str> {
        let dash_boundary: &[u8] = &[b"--", boundary].concat();
        let delimiter: &[u8] = &[b"\r\n", dash_boundary].concat();
        let close_delimiter: &[u8] = &[b"\r\n", dash_boundary, b"--"].concat();

        if let Some(idx) = data.index_of(dash_boundary) {
            let mut parts = Vec::new();

            let mut i = idx + dash_boundary.len();

            loop {
                if let Some(idx) = data[i..].index_of(delimiter) {
                    let skipped =
                        syntax::index_skipping_transport_padding_and_crlf(&data[i..i + idx]);

                    let content = &data[i + skipped..i + idx];

                    match Body::construct_message(content) {
                        Ok(message) => {
                            parts.push(Arc::new(message));
                        }

                        Err(e) => {
                            return Err(e);
                        }
                    }

                    if data[i + idx..].starts_with(close_delimiter) {
                        break;
                    } else {
                        i = i + idx + delimiter.len();
                    }
                } else {
                    break;
                }
            }

            return Ok(MultipartBody {
                boundary: boundary.to_vec(),
                parts,
            });
        }

        Err("unrespected boundary")
    }

    fn get_dash_boundary_readers<'a>(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        readers.push(Box::new(&b"--"[..]));
        readers.push(Box::new(&self.boundary[..]));
    }

    fn get_delimeter_readers<'a>(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        readers.push(Box::new(&b"\r\n"[..]));
        self.get_dash_boundary_readers(readers);
    }

    fn get_close_delimeter_readers<'a>(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        readers.push(Box::new(&b"\r\n"[..]));
        self.get_dash_boundary_readers(readers);
        readers.push(Box::new(&b"--"[..]));
    }

    pub fn get_readers<'a>(
        &'a self,
        readers: &mut Vec<Box<dyn Read + Send + 'a>>,
    ) -> Result<(), BodySerializationError> {
        let mut first_part = true;
        for part in &self.parts {
            if first_part {
                first_part = false;
                self.get_dash_boundary_readers(readers);
            } else {
                self.get_delimeter_readers(readers);
            }
            readers.push(Box::new(&b"\r\n"[..]));
            readers.push(Box::new(part.reader()?));
        }

        self.get_close_delimeter_readers(readers);

        Ok(())
    }
}

impl Clone for MultipartBody {
    fn clone(&self) -> Self {
        let mut parts = Vec::new();
        for part in &self.parts {
            parts.push(part.clone());
        }
        MultipartBody {
            boundary: self.boundary.clone(),
            parts,
        }
    }
}

impl Serializable for MultipartBody {
    // fn serialize(&self) -> Vec<u8> {
    //     let dash_boundary: &[u8] = &[b"--", &self.boundary[..]].concat();
    //     let delimiter: &[u8] = &[b"\r\n", dash_boundary].concat();
    //     let close_delimiter: &[u8] = &[b"\r\n", dash_boundary, b"--"].concat();

    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     let mut first_part = true;
    //     for part in &self.parts {
    //         if first_part {
    //             first_part = false;
    //             data.extend_from_slice(delimiter);
    //         } else {
    //             data.extend_from_slice(dash_boundary);
    //         }
    //         data.extend(b"\r\n");
    //         data.extend(part.serialize());
    //     }

    //     data.extend_from_slice(close_delimiter);
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;

        let dash_boundary_len = 2 + self.boundary.len();
        let delimiter_len = 2 + dash_boundary_len;
        let close_delimiter_len = 2 + dash_boundary_len + 2;

        let mut first_part = true;
        for part in &self.parts {
            if first_part {
                first_part = false;
                size += dash_boundary_len;
            } else {
                size += delimiter_len;
            }
            size += 2;
            size += part.estimated_size();
        }

        size += close_delimiter_len;
        size
    }
}
