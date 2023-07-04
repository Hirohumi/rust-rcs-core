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

use crate::internet::header::headers_get_readers;
use crate::io::Serializable;
use crate::util::raw_string::{StrEq, StrFind, ToInt};

use super::super::header::Header;
use super::super::header_field::AsHeaderField;
use super::super::headers::content_type::AsContentType;
use super::{Body, BodySerializationError};

#[derive(Debug)]
pub struct MessageBody {
    pub headers: Vec<Header>,
    pub body: Arc<Body>,
}

impl MessageBody {
    pub fn construct(data: &[u8]) -> Result<MessageBody, &'static str> {
        let mut headers = Vec::new();
        let mut i = 0;
        while i <= data.len() {
            if let Some(idx) = data[i..].index_of(b"\r\n") {
                if idx == 0 {
                    i = i + 2;
                    break;
                }
                let mut iter = data[i..i + idx].iter();
                if let Some(position) = iter.position(|c| *c == b':') {
                    headers.push(Header::new(
                        data[i..i + position].to_vec(),
                        iter.cloned().collect::<Vec<u8>>(),
                    ));
                } else {
                    return Err("malformed header");
                }
                i = i + idx + 2;
            } else {
                break;
            }
        }

        let mut construct_flag: Option<i32> = None;
        let mut content_length: Option<usize> = None;
        let mut boundary: Option<Vec<u8>> = None;

        for header in &headers {
            if header.get_name().equals_bytes(b"Content-Length", false) {
                if let Ok(i) = header.get_value().to_int() {
                    content_length = Some(i);
                }
            } else if header.get_name().equals_bytes(b"Content-Type", false) {
                let field = header.get_value().as_header_field();
                if let Some(content_type) = field.as_content_type() {
                    if content_type.major_type.equals_bytes(b"message", true) {
                        construct_flag = Some(1);
                    } else if content_type.major_type.equals_bytes(b"multipart", true) {
                        construct_flag = Some(2);
                        boundary = Some(content_type.boundary.to_vec());
                    } else {
                        construct_flag = Some(0);
                    }
                }
            }
        }

        match content_length {
            Some(content_length) => {
                if i + content_length < data.len() {
                    return Err("insufficient data length");
                }

                match construct_flag {
                    Some(flag) => match flag {
                        0 => {
                            return Ok(MessageBody {
                                headers,
                                body: Arc::new(Body::construct_raw(&data[i..i + content_length])),
                            });
                        }
                        1 => match Body::construct_message(&data[i..i + content_length]) {
                            Ok(body) => {
                                return Ok(MessageBody {
                                    headers,
                                    body: Arc::new(body),
                                });
                            }
                            Err(e) => {
                                return Err(e);
                            }
                        },
                        2 => {
                            if let Some(boundary) = boundary {
                                match Body::construct_multipart(
                                    &data[i..i + content_length],
                                    &boundary,
                                ) {
                                    Ok(body) => {
                                        return Ok(MessageBody {
                                            headers,
                                            body: Arc::new(body),
                                        });
                                    }
                                    Err(e) => {
                                        return Err(e);
                                    }
                                }
                            } else {
                                return Err("missing multipart boundary");
                            }
                        }
                        _ => {
                            panic!("impossible condition")
                        }
                    },
                    None => {
                        return Ok(MessageBody {
                            headers,
                            body: Arc::new(Body::construct_raw(&data[i..i + content_length])),
                        });
                    }
                }
            }

            None => {
                return Ok(MessageBody {
                    headers,
                    body: Arc::new(Body::construct_raw(&data[i..])),
                });
            }
        }
    }

    pub fn get_readers<'a>(
        &'a self,
        readers: &mut Vec<Box<dyn Read + Send + 'a>>,
    ) -> Result<(), BodySerializationError> {
        headers_get_readers(&self.headers, readers);

        readers.push(Box::new(&b"\r\n"[..]));
        readers.push(Box::new(self.body.reader()?));

        Ok(())
    }
}

impl Clone for MessageBody {
    fn clone(&self) -> Self {
        let mut headers = Vec::new();
        for header in &self.headers {
            headers.push(header.clone());
        }
        MessageBody {
            headers,
            body: self.body.clone(),
        }
    }
}

impl Serializable for MessageBody {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     data.extend(self.headers.serialize());
    //     data.extend(b"\r\n");
    //     data.extend(self.body.serialize());
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.headers.estimated_size();
        size += 2;
        size += self.body.estimated_size();
        size
    }
}
