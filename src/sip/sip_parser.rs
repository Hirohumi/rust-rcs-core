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

use std::sync::Arc;

use crate::internet::body::Body;
use crate::internet::header;
use crate::internet::header::{Header, HeaderSearch};
use crate::internet::header_field::AsHeaderField;
use crate::internet::headers::content_type::AsContentType;
use crate::internet::syntax;
use crate::util::raw_string::{StrEq, ToInt};

use super::sip_message::{SipFirstLine, SipMessage};

enum ParsingState {
    Empty,
    ReadingFirstLine,
    ReadingHeaders(Option<SipFirstLine>, Option<Vec<Header>>, Option<Vec<u8>>),
    ExpectingBody(Option<SipFirstLine>, Option<Vec<Header>>, usize),
}

pub struct SipParser {
    buffer: Vec<u8>,
    p: usize,
    state: ParsingState,
}

impl SipParser {
    pub fn new() -> SipParser {
        SipParser {
            buffer: Vec::new(),
            p: 0,
            state: ParsingState::Empty,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn produce(&mut self) -> Result<Option<SipMessage>, &str> {
        'outer: loop {
            match &mut self.state {
                ParsingState::Empty => {
                    if self.p < self.buffer.len() {
                        let c1 = self.buffer[self.p];

                        if c1 == b'\r' {
                            if self.p + 1 < self.buffer.len() {
                                let c2 = self.buffer[self.p + 1];

                                if c2 == b'\n' {
                                    if self.p + 3 < self.buffer.len() {
                                        let c3 = self.buffer[self.p + 2];
                                        let c4 = self.buffer[self.p + 3];

                                        if c3 == b'\r' && c4 == b'\n' {
                                            self.p = self.p + 4;

                                            return Ok(Some(SipMessage::Ping));
                                        }
                                    }

                                    self.p = self.p + 2;

                                    return Ok(Some(SipMessage::Pong));
                                } else {
                                    return Err("dangling Carriage Return\n");
                                }
                            } else {
                                return Ok(None);
                            }
                        }

                        self.state = ParsingState::ReadingFirstLine;
                    } else {
                        return Ok(None);
                    }
                }

                ParsingState::ReadingFirstLine => {
                    let buf = &self.buffer[self.p..];

                    if let Ok(o) = SipFirstLine::decode_first_line(buf) {
                        match o {
                            Some((first_line, consumed)) => {
                                self.p = self.p + consumed;
                                self.state = ParsingState::ReadingHeaders(
                                    Some(first_line),
                                    Some(Vec::new()),
                                    Some(Vec::new()),
                                );
                            }

                            None => return Ok(None),
                        }
                    } else {
                        return Err("error decoding first line");
                    }
                }

                ParsingState::ReadingHeaders(first_line, message_headers, line) => {
                    let mut first_fold: Option<usize> = None;
                    let mut last_fold: usize = 0;

                    'inner: loop {
                        let chunk = &self.buffer[self.p + last_fold..];

                        let mut iter = chunk.iter();

                        if let Some(position) = iter.position(|c| *c == b'\r') {
                            if let Some(c) = iter.next() {
                                if *c == b'\n' {
                                    if last_fold + position == 0 {
                                        self.p = self.p + 2;
                                        let mut content_length: Option<usize> = None;
                                        if let Some(headers) = message_headers {
                                            if let Some(content_length_header) =
                                                header::search(headers, b"Content-Length", true)
                                            {
                                                if let Ok(i) =
                                                    content_length_header.get_value().to_int()
                                                {
                                                    content_length = Some(i);
                                                }
                                            }
                                        }

                                        if let Some(content_length) = content_length {
                                            self.state = ParsingState::ExpectingBody(
                                                first_line.take(),
                                                message_headers.take(),
                                                content_length,
                                            );
                                            continue 'outer;
                                        } else {
                                            return Err("require explicit content-length");
                                        }
                                    }

                                    if let Some(c) = iter.next() {
                                        if *c == b'\t' {
                                            if first_fold.is_none() {
                                                first_fold = Some(position);
                                            }
                                            last_fold = last_fold + position + 3;
                                            if let Some(line) = line {
                                                line.extend_from_slice(&chunk[..position]);
                                                line.push(b' ');
                                            } else {
                                                panic!("line value missing for no obvious reason")
                                            }
                                            continue 'inner;
                                        }
                                    }

                                    if let Some(mut line) = line.take() {
                                        line.extend_from_slice(&chunk[..position]);
                                        let mut iter = line.iter();

                                        if let Some(idx) = iter.position(|c| *c == b':') {
                                            if let Some(first_fold) = first_fold {
                                                if first_fold < idx {
                                                    return Err("obsolete line foldings are not allowed in header names");
                                                }
                                            }
                                            match message_headers {
                                                Some(headers) => {
                                                    headers.push(Header::new(
                                                        syntax::trim(&line[..idx]).to_vec(),
                                                        syntax::trim(&line[idx + 1..]).to_vec(),
                                                    ));
                                                    self.p = self.p + last_fold + position + 2;
                                                    self.state = ParsingState::ReadingHeaders(
                                                        first_line.take(),
                                                        message_headers.take(),
                                                        Some(Vec::new()),
                                                    );
                                                    continue 'outer;
                                                }
                                                None => {
                                                    panic!("message_headers value missing for no obvious reason")
                                                }
                                            }
                                        } else {
                                            return Err("require header name");
                                        }
                                    } else {
                                        panic!("line value missing for no obvious reason")
                                    }
                                } else {
                                    return Err("dangling Carriage Return");
                                }
                            }
                        }

                        return Ok(None);
                    }
                }

                ParsingState::ExpectingBody(first_line, message_headers, content_length) => {
                    if self.p + *content_length <= self.buffer.len() {
                        if let Some(headers) = message_headers {
                            let mut construct_flag: Option<i32> = None;
                            let mut boundary: Option<Vec<u8>> = None;

                            for header in HeaderSearch::new(headers, b"Content-Type", true) {
                                let field = header.get_value().as_header_field();
                                if let Some(content_type) = field.as_content_type() {
                                    if content_type.major_type.equals_bytes(b"message", true) {
                                        construct_flag = Some(1);
                                    } else if content_type
                                        .major_type
                                        .equals_bytes(b"multipart", true)
                                    {
                                        construct_flag = Some(2);
                                        boundary = Some(content_type.boundary.to_vec());
                                    } else {
                                        construct_flag = Some(0);
                                    }
                                }
                            }

                            if *content_length == 0 {
                                let ok = Ok(Some(SipMessage::new(
                                    first_line.take().unwrap(),
                                    message_headers.take(),
                                    None,
                                )));
                                self.buffer = self.buffer.split_off(self.p);
                                self.p = 0;
                                self.state = ParsingState::Empty;
                                return ok;
                            }

                            match construct_flag {
                                Some(flag) => match flag {
                                    0 => {
                                        let body = Body::construct_raw(
                                            &self.buffer[self.p..self.p + *content_length],
                                        );
                                        let ok = Ok(Some(SipMessage::new(
                                            first_line.take().unwrap(),
                                            message_headers.take(),
                                            Some(Arc::new(body)),
                                        )));
                                        self.buffer =
                                            self.buffer.split_off(self.p + *content_length);
                                        self.p = 0;
                                        self.state = ParsingState::Empty;
                                        return ok;
                                    }
                                    1 => match Body::construct_message(
                                        &self.buffer[self.p..self.p + *content_length],
                                    ) {
                                        Ok(body) => {
                                            let ok = Ok(Some(SipMessage::new(
                                                first_line.take().unwrap(),
                                                message_headers.take(),
                                                Some(Arc::new(body)),
                                            )));
                                            self.buffer =
                                                self.buffer.split_off(self.p + *content_length);
                                            self.p = 0;
                                            self.state = ParsingState::Empty;
                                            return ok;
                                        }
                                        Err(e) => {
                                            return Err(e);
                                        }
                                    },
                                    2 => {
                                        if let Some(boundary) = boundary {
                                            match Body::construct_multipart(
                                                &self.buffer[self.p..self.p + *content_length],
                                                &boundary,
                                            ) {
                                                Ok(body) => {
                                                    let ok = Ok(Some(SipMessage::new(
                                                        first_line.take().unwrap(),
                                                        message_headers.take(),
                                                        Some(Arc::new(body)),
                                                    )));
                                                    self.buffer = self
                                                        .buffer
                                                        .split_off(self.p + *content_length);
                                                    self.p = 0;
                                                    self.state = ParsingState::Empty;
                                                    return ok;
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
                                    panic!("require explicit content-type")
                                }
                            }
                        }

                        return Err("seriously?");
                    } else {
                        return Ok(None);
                    }
                }
            }
        }
    }
}
