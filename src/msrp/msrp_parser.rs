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

use crate::internet::header;
use crate::internet::header::Header;
use crate::internet::headers::byte_range;
use crate::internet::syntax;

use crate::util::raw_string::{StrFind, ToInt};

use super::msrp_chunk::ContinuationFlag;
use super::msrp_chunk::MsrpChunk;
use super::msrp_chunk::MsrpRequestLine;
use super::msrp_chunk::MsrpResponseLine;

enum MsrpFirstLine {
    Request(MsrpRequestLine),
    Response(MsrpResponseLine),
}

impl MsrpFirstLine {
    fn transaction_id(&self) -> &Vec<u8> {
        match self {
            MsrpFirstLine::Request(req_line) => &req_line.transaction_id,
            MsrpFirstLine::Response(resp_line) => &resp_line.transaction_id,
        }
    }
}

fn new_msrp_chunk(
    first_line: MsrpFirstLine,
    headers: Vec<Header>,
    body: Option<Vec<u8>>,
    continuation_flag: ContinuationFlag,
) -> MsrpChunk {
    match first_line {
        MsrpFirstLine::Request(req_line) => {
            MsrpChunk::new_request_chunk(req_line, headers, body, continuation_flag)
        }
        MsrpFirstLine::Response(resp_line) => MsrpChunk::new_response_chunk(resp_line, headers),
    }
}

enum ParsingState {
    ReadingFirstLine,
    ReadingHeaders(Option<MsrpFirstLine>, Option<Vec<Header>>),
    ReadingBody(
        Option<MsrpRequestLine>,
        Option<Vec<Header>>,
        Option<usize>,
        usize,
    ),
}

pub struct MsrpParser {
    buffer: Vec<u8>,
    p: usize,
    state: ParsingState,
}

impl MsrpParser {
    pub fn new() -> MsrpParser {
        MsrpParser {
            buffer: Vec::new(),
            p: 0,
            state: ParsingState::ReadingFirstLine,
        }
    }

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn produce(&mut self) -> Result<Option<MsrpChunk>, &str> {
        'outer: loop {
            match &mut self.state {
                ParsingState::ReadingFirstLine => {
                    let mut i = 0;
                    while self.p + i < self.buffer.len() {
                        let b1 = self.buffer[self.p + i];
                        if b1 == b'\r' {
                            if self.p + i + 1 < self.buffer.len() {
                                let b2 = self.buffer[self.p + i + 1];
                                if b2 == b'\n' {
                                    let mut iter =
                                        self.buffer[self.p..self.p + i].splitn(3, |c| *c == b' ');
                                    if let Some(s1) = iter.next() {
                                        if s1 == b"MSRP" {
                                            if let Some(s2) = iter.next() {
                                                if let Some(s3) = iter.next() {
                                                    let s4;
                                                    let s5;
                                                    if let Some(idx) =
                                                        s3.iter().position(|c| *c == b' ')
                                                    {
                                                        s4 = &s3[..idx];
                                                        s5 = Some(s3[idx + 1..].to_vec());
                                                    } else {
                                                        s4 = s3;
                                                        s5 = None;
                                                    }

                                                    if s4.len() == 3
                                                        && s4[0] >= b'0'
                                                        && s4[0] <= b'9'
                                                        && s4[1] >= b'0'
                                                        && s4[1] <= b'9'
                                                        && s4[2] >= b'0'
                                                        && s4[2] <= b'9'
                                                    {
                                                        if let Ok(status_code) = s4.to_int() {
                                                            let resp_line = MsrpResponseLine {
                                                                transaction_id: s2.to_vec(),
                                                                status_code,
                                                                comment: s5,
                                                            };

                                                            self.state =
                                                                ParsingState::ReadingHeaders(
                                                                    Some(MsrpFirstLine::Response(
                                                                        resp_line,
                                                                    )),
                                                                    Some(Vec::new()),
                                                                );
                                                            self.p = self.p + i + 2;

                                                            continue 'outer;
                                                        }
                                                    } else {
                                                        if let None = s5 {
                                                            let req_line = MsrpRequestLine {
                                                                transaction_id: s2.to_vec(),
                                                                request_method: s4.to_vec(),
                                                            };

                                                            self.state =
                                                                ParsingState::ReadingHeaders(
                                                                    Some(MsrpFirstLine::Request(
                                                                        req_line,
                                                                    )),
                                                                    Some(Vec::new()),
                                                                );
                                                            self.p = self.p + i + 2;

                                                            continue 'outer;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    return Err("Bad format");
                                }
                            }
                        }

                        i = i + 1;
                    }
                }

                ParsingState::ReadingHeaders(first_line, headers) => {
                    let mut i = 0;
                    while self.p + i < self.buffer.len() {
                        let b1 = self.buffer[self.p + i];
                        if b1 == b'\r' {
                            if self.p + i + 1 < self.buffer.len() {
                                let b2 = self.buffer[self.p + i + 1];
                                if b2 == b'\n' {
                                    if let Some(first_line_) = first_line {
                                        let transaction_id = first_line_.transaction_id();

                                        if let Some(idx) =
                                            self.buffer[self.p..self.p + i].index_of(b"-------")
                                        {
                                            if idx + 7 + transaction_id.len() == i {
                                                if &self.buffer[self.p + idx + 7..self.p + i]
                                                    == transaction_id
                                                {
                                                    self.buffer =
                                                        self.buffer.split_off(self.p + i + 2);
                                                    self.p = 0;
                                                    let ok = Ok(Some(new_msrp_chunk(
                                                        first_line.take().unwrap(),
                                                        headers.take().unwrap(),
                                                        None,
                                                        ContinuationFlag::Complete,
                                                    )));
                                                    self.state = ParsingState::ReadingFirstLine;
                                                    return ok;
                                                }
                                            }
                                        }

                                        if i == 0 {
                                            if let Some(first_line) = first_line.take() {
                                                match first_line {
                                                    MsrpFirstLine::Request(req_line) => {
                                                        if let Some(headers) = headers.take() {
                                                            if let Some(byte_range_header) = header::search(&headers, b"Byte-Range", false) {
                                                                let byte_range_header_value = byte_range_header.get_value();
                                                                if let Some(byte_range) = byte_range::parse(byte_range_header_value) {
                                                                    if let Some(to) = byte_range.to {
                                                                        self.state = ParsingState::ReadingBody(Some(req_line), Some(headers), Some(to + 1 - byte_range.from), byte_range.total + 1 - byte_range.from);
                                                                        self.p = self.p + 2;
                                                                        continue 'outer;
                                                                    } else {
                                                                        self.state = ParsingState::ReadingBody(Some(req_line), Some(headers), None, byte_range.total + 1 - byte_range.from);
                                                                        self.p = self.p + 2;
                                                                        continue 'outer;
                                                                    }
                                                                }
                                                            }

                                                            self.state = ParsingState::ReadingBody(Some(req_line), Some(headers), None, 0);
                                                            self.p = self.p + 2;
                                                            continue 'outer;

                                                        } else {
                                                            return Err("impossible condition");
                                                        }
                                                    }

                                                    MsrpFirstLine::Response(_) => {
                                                        return Err("MSRP Responses are not allowed to have body")
                                                    }
                                                }
                                            } else {
                                                return Err("impossible condition");
                                            }
                                        } else {
                                            let line = &self.buffer[self.p..self.p + i];

                                            if let Some(idx) = line.iter().position(|c| *c == b':')
                                            {
                                                match headers {
                                                    Some(headers) => {
                                                        headers.push(Header::new(
                                                            syntax::trim(&line[..idx]).to_vec(),
                                                            syntax::trim(&line[idx + 1..]).to_vec(),
                                                        ));
                                                        self.p = self.p + i + 2;
                                                        continue 'outer;
                                                    }
                                                    _ => {
                                                        return Err("impossible condition");
                                                    }
                                                }
                                            } else {
                                                return Err("Bad format");
                                            }
                                        }
                                    } else {
                                        return Err("impossible condition");
                                    }
                                }
                            }
                        }

                        i = i + 1;
                    }
                }

                ParsingState::ReadingBody(req_line, headers, content_length, range_limit) => {
                    if let Some(req_line_) = req_line {
                        if let Some(content_length) = content_length {
                            let mut boundary = b"\r\n-------".to_vec();
                            boundary.extend(&req_line_.transaction_id);
                            boundary.extend(b"\r\n");

                            if self.buffer[self.p + *content_length..].start_with(&boundary) {
                                let data = self.buffer[self.p..self.p + *content_length].to_vec();
                                self.buffer = self
                                    .buffer
                                    .split_off(self.p + *content_length + boundary.len());
                                self.p = 0;
                                return Ok(Some(MsrpChunk::new_request_chunk(
                                    req_line.take().unwrap(),
                                    headers.take().unwrap(),
                                    Some(data),
                                    ContinuationFlag::Complete,
                                )));
                            }

                            if self.p + *content_length + boundary.len() <= self.buffer.len() {
                                return Err("Missing closing boundary");
                            } else {
                                return Ok(None);
                            }
                        } else {
                            let mut continuation_flag = None;

                            if let Some(idx) = self.buffer[self.p..].index_of(b"\r\n-------") {
                                if self.buffer[self.p + idx + 9..]
                                    .start_with(&req_line_.transaction_id)
                                {
                                    if self.buffer
                                        [self.p + idx + 9 + req_line_.transaction_id.len()..]
                                        .start_with(b"$\r\n")
                                    {
                                        continuation_flag = Some((idx, ContinuationFlag::Complete));
                                    } else if self.buffer
                                        [self.p + idx + 9 + req_line_.transaction_id.len()..]
                                        .start_with(b"#\r\n")
                                    {
                                        continuation_flag = Some((idx, ContinuationFlag::Abort));
                                    } else if self.buffer
                                        [self.p + idx + 9 + req_line_.transaction_id.len()..]
                                        .start_with(b"+\r\n")
                                    {
                                        continuation_flag =
                                            Some((idx, ContinuationFlag::Continuation));
                                    }
                                }
                            }

                            if let Some((idx, continuation_flag)) = continuation_flag {
                                if idx < *range_limit {
                                    let data = self.buffer[self.p..self.p + idx].to_vec();
                                    self.buffer = self.buffer.split_off(
                                        self.p + idx + 9 + req_line_.transaction_id.len() + 3,
                                    );
                                    self.p = 0;
                                    let ok = Ok(Some(MsrpChunk::new_request_chunk(
                                        req_line.take().unwrap(),
                                        headers.take().unwrap(),
                                        Some(data),
                                        continuation_flag,
                                    )));
                                    self.state = ParsingState::ReadingFirstLine;
                                    return ok;
                                } else {
                                    return Err("More data than declared");
                                }
                            } else {
                                if self.p + *range_limit + 9 + req_line_.transaction_id.len() + 3
                                    <= self.buffer.len()
                                {
                                    return Err("Missing closing boundary");
                                }

                                return Ok(None);
                            }
                        }
                    } else {
                        return Err("impossible condition");
                    }
                }
            }
        }
    }
}
