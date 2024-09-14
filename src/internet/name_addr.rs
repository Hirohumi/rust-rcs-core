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

use crate::internet::syntax;
use crate::io::{DynamicChain, Serializable};

use super::parameter::ParameterParser;

pub struct NameAddr<'a> {
    pub display_name: Option<&'a [u8]>,
    pub uri_part: Option<NameAddrUri<'a>>,
}

impl<'a> NameAddr<'a> {
    fn from_name_uri(name: Option<&'a [u8]>, uri: Option<&'a [u8]>) -> NameAddr<'a> {
        if let Some(uri) = uri {
            if let Some(idx) = syntax::index_with_token_escaping(uri, b';') {
                NameAddr {
                    display_name: name,
                    uri_part: Some(NameAddrUri {
                        uri: &uri[..idx],
                        // uri_parameters: parameter::parse_parameters(&uri[idx + 1..], b';'),
                        uri_parameters: &uri[idx + 1..],
                    }),
                }
            } else {
                NameAddr {
                    display_name: name,
                    uri_part: Some(NameAddrUri {
                        uri,
                        uri_parameters: &[],
                    }),
                }
            }
        } else {
            NameAddr {
                display_name: name,
                uri_part: None,
            }
        }
    }

    // pub fn uri_part_to_string(&self) -> Option<Vec<u8>> {
    //     if let Some(uri_part) = &self.uri_part {
    //         let (uri, uri_parameters) = uri_part;
    //         let mut uri = uri.to_vec();
    //         for p in uri_parameters {
    //             uri.extend(b";");
    //             uri.extend_from_slice(p.name);
    //             if let Some(v) = p.value {
    //                 uri.extend(b"=");
    //                 uri.extend_from_slice(v);
    //             }
    //         }
    //         return Some(uri);
    //     }

    //     None
    // }

    pub fn get_readers(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        if let Some(display_name) = self.display_name {
            readers.push(Box::new(&b"\""[..]));
            readers.push(Box::new(&display_name[..]));
            readers.push(Box::new(&b"\""[..]));
            if let Some(_) = self.uri_part {
                readers.push(Box::new(&b", "[..]));
            }
        }

        if let Some(uri_part) = &self.uri_part {
            readers.push(Box::new(&b"<"[..]));
            uri_part.get_readers(readers);
            readers.push(Box::new(&b">"[..]));
        }

        // if let Some(uri_part) = self.uri_part {
        //     let uri_part_reader = uri_part.reader();
        //     NameAddrReader{
        //         display_name: self.display_name,
        //         uri_part: Some(uri_part_reader),
        //         uri_part_length: uri_part.estimated_size(),
        //         pos: 0,
        //     }
        // } else {
        //     NameAddrReader{
        //         display_name: self.display_name,
        //         uri_part: None,
        //         uri_part_length: 0,
        //         pos: 0,
        //     }
        // }
    }
}

pub struct NameAddrUri<'a> {
    pub uri: &'a [u8],
    pub uri_parameters: &'a [u8],
}

impl<'a> NameAddrUri<'a> {
    pub fn get_parameter_iterator(&'a self) -> ParameterParser<'a> {
        ParameterParser::new(self.uri_parameters, b';', false)
    }

    pub fn get_readers(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        readers.push(Box::new(&self.uri[..]));
        readers.push(Box::new(&self.uri_parameters[..]));

        // for p in self.get_parameter_iterator() {
        //     readers.push(Box::new(p.reader()));
        // }
    }
}

pub trait AsNameAddr<'a> {
    type Target;
    fn as_name_addresses(&'a self) -> Vec<Self::Target>;
}

impl<'a> AsNameAddr<'a> for [u8] {
    type Target = NameAddr<'a>;
    fn as_name_addresses(&'a self) -> Vec<NameAddr> {
        let mut name_addresses = Vec::new();

        let mut i = 0;

        let mut quoted_name: Option<&[u8]> = None;
        let mut bracket_uri: Option<&[u8]> = None;

        let mut uri_spec_start_index = 0;

        while i < self.len() {
            let c = self[i];

            if c == b'"' {
                if let Some(idx) = syntax::index_with_character_escaping(&self[i + 1..], b'"') {
                    quoted_name = Some(&self[i + 1..i + idx + 1]);
                    i = i + idx;
                }
            } else if c == b'<' {
                if let Some(idx) = syntax::index_with_character_escaping(&self[i + 1..], b'>') {
                    bracket_uri = Some(&self[i + 1..i + idx + 1]);
                    i = i + idx;
                }
            } else if c == b',' || i + 1 == self.len() {
                match (quoted_name.take(), bracket_uri.take()) {
                    (Some(quoted_name), Some(bracket_uri)) => {
                        let name = syntax::unquote(quoted_name);
                        let uri = syntax::undo_bracket(bracket_uri);
                        let name_addr = NameAddr::from_name_uri(Some(name), Some(uri));
                        name_addresses.push(name_addr);
                    }

                    (Some(quoted_name), None) => {
                        let name = syntax::unquote(quoted_name);
                        let name_addr = NameAddr::from_name_uri(Some(name), None);
                        name_addresses.push(name_addr);
                    }

                    (None, Some(bracket_uri)) => {
                        let uri = syntax::undo_bracket(bracket_uri);
                        let name_addr = NameAddr::from_name_uri(None, Some(uri));
                        name_addresses.push(name_addr);
                    }

                    (None, None) => {
                        let end = if i + 1 == self.len() { i + 1 } else { i };
                        let uri = syntax::trim(&self[uri_spec_start_index..end]);
                        let name_addr = NameAddr::from_name_uri(None, Some(uri));
                        name_addresses.push(name_addr);
                    }
                }

                uri_spec_start_index = i + 1;
            }

            i = i + 1;
        }

        name_addresses
    }
}

impl<'a> Serializable for NameAddr<'a> {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     if let Some(display_name) = self.display_name {
    //         data.extend(b"\"");
    //         data.extend_from_slice(display_name);
    //         data.extend(b"\"");
    //         if let Some(_) = self.uri_part {
    //             data.extend(b", ");
    //         }
    //     }
    //     if let Some(uri_part_string) = self.uri_part_to_string() {
    //         data.extend(b"<");
    //         data.extend(uri_part_string);
    //         data.extend(b">");
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        if let Some(display_name) = self.display_name {
            size += 1;
            size += display_name.len();
            size += 1;
            if let Some(_) = self.uri_part {
                size += 2;
            }
        }
        if let Some(uri_part) = &self.uri_part {
            size += 1;
            size += uri_part.estimated_size();
            size += 1;
        }
        // if let Some(uri_part_string) = self.uri_part_to_string() {
        //     size += 1;
        //     size += uri_part_string.len();
        //     size += 1;
        // }
        size
    }
}

impl<'a> Serializable for NameAddrUri<'a> {
    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.uri.len();
        for parameter in self.get_parameter_iterator() {
            size += 1;
            size += parameter.name.len();
            if let Some(v) = parameter.value {
                size += 1;
                size += v.len();
            }
        }

        size
    }
}

// pub struct NameAddrReader<'a> {
//     display_name: Option<&'a [u8]>,
//     uri_part: Option<NameAddrUriReader<'a>>,
//     uri_part_length: usize,
//     pos: usize,
// }

// impl<'a> Read for NameAddrReader<'a> {
//     fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
//         let mut i = 0;
//         let mut first_part_size = 0;
//         if let Some(display_name) = self.display_name {
//             while self.pos + i < 1 && i < buf.len() {
//                 buf[i] = b'\"';
//                 i += 1;
//             }
//             while self.pos + i >= 1 && self.pos + i < 1 + display_name.len() && i < buf.len() {
//                 buf[i] = display_name[self.pos + i - 1];
//                 i += 1;
//             }
//             while self.pos + i >= 1 + display_name.len() && self.pos + i < 1 + display_name.len() + 1 && i < buf.len() {
//                 buf[i] = b'\"';
//                 i += 1;
//             }
//             if let Some(_) = self.uri_part {
//                 while self.pos + i >= 1 + display_name.len() + 1 && self.pos + i < 1 + display_name.len() + 1 + 2 && i < buf.len() {
//                     if self.pos + i == 1 + display_name.len() + 1 {
//                         buf[i] = b',';
//                     } else if self.pos + i == 1 + display_name.len() + 1 + 1 {
//                         buf[i] = b' ';
//                     }
//                     i += 1;
//                 }
//                 first_part_size = 1 + display_name.len() + 1 + 2;
//             } else {
//                 first_part_size = 1 + display_name.len() + 1;
//             }
//         }
//         if self.pos + i >= first_part_size {
//             if let Some(uri_part) = self.uri_part {
//                 while self.pos + i >= first_part_size + 1 && i < buf.len() {
//                     buf[i] = b'<';
//                     i += 1;
//                 }
//                 while i < buf.len() {
//                     match uri_part.read(&mut buf[i..]) {
//                         Ok(r) => {
//                             if r == 0 {
//                                 break;
//                             } else {
//                                 i += r;
//                             }
//                         }

//                         Err(e) => {
//                             return Err(e);
//                         }
//                     }
//                 }
//                 while self.pos +i >= first_part_size + 1 + self.uri_part_length && self.pos + i < first_part_size + 1 + self.uri_part_length + 1 && i < buf.len() {
//                     buf[i] = b'>';
//                     i += 1;
//                 }
//             }
//         }
//         self.pos += i;
//         Ok(i)
//     }
// }

pub struct NameAddrUriReader<'a> {
    uri: &'a [u8],
    chain: DynamicChain<'a>,
    pos: usize,
}

impl<'a> Read for NameAddrUriReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < self.uri.len() && i < buf.len() {
            buf[i] = self.uri[self.pos + i];
            i += 1;
        }
        if self.pos + i >= self.uri.len() {
            while i < buf.len() {
                match self.chain.read(&mut buf[i..]) {
                    Ok(r) => {
                        if r == 0 {
                            break;
                        } else {
                            i += r;
                        }
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }
        self.pos += i;
        Ok(i)
    }
}
