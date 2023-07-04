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

use crate::internet::header::Header;
use crate::internet::header::{self, headers_get_readers};

use crate::io::Serializable;

use super::headers::status::AsMsrpStatus;

pub enum ContinuationFlag {
    Complete,
    Abort,
    Continuation,
}

pub struct MsrpRequestLine {
    pub transaction_id: Vec<u8>,
    pub request_method: Vec<u8>,
}

impl MsrpRequestLine {
    pub fn reader(&self) -> MsrpRequestLineReader {
        MsrpRequestLineReader {
            transaction_id: &self.transaction_id,
            request_method: &self.request_method,
            pos: 0,
        }
    }
}

impl Serializable for MsrpRequestLine {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     data.extend(b"MSRP ");
    //     data.extend(&self.transaction_id);
    //     data.extend(b" ");
    //     data.extend(&self.request_method);
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += 5;
        size += self.transaction_id.len();
        size += 1;
        size += self.request_method.len();
        size
    }
}

pub struct MsrpRequestLineReader<'a> {
    transaction_id: &'a [u8],
    request_method: &'a [u8],
    pos: usize,
}

impl<'a> Read for MsrpRequestLineReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < 5 && i < buf.len() {
            buf[i] = b"MSRP "[self.pos + i];
            i += 1;
        }
        while self.pos + i >= 5 && self.pos + i < 5 + self.transaction_id.len() && i < buf.len() {
            buf[i] = self.transaction_id[self.pos + i - 5];
            i += 1;
        }
        while self.pos + i >= 5 + self.transaction_id.len()
            && self.pos + i < 5 + self.transaction_id.len() + 1
            && i < buf.len()
        {
            buf[i] = b' ';
            i += 1;
        }
        while self.pos + i >= 5 + self.transaction_id.len() + 1
            && self.pos + i < 5 + self.transaction_id.len() + 1 + self.request_method.len()
            && i < buf.len()
        {
            buf[i] = self.request_method[self.pos + i - 5 - self.transaction_id.len() - 1];
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}

pub struct MsrpResponseLine {
    pub transaction_id: Vec<u8>,
    pub status_code: u16,
    pub comment: Option<Vec<u8>>,
}

impl MsrpResponseLine {
    pub fn reader(&self) -> MsrpResponseLineReader {
        MsrpResponseLineReader {
            transaction_id: &self.transaction_id,
            status_code: format!("{:0>3}", self.status_code),
            comment: match &self.comment {
                Some(comment) => Some(comment),
                None => None,
            },
            pos: 0,
        }
    }
}

impl Serializable for MsrpResponseLine {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     data.extend(b"MSRP ");
    //     data.extend(&self.transaction_id);
    //     let status_code = format!(" {:0>3}", self.status_code);
    //     let status_code = status_code.as_bytes();
    //     data.extend(status_code);
    //     if let Some(comment) = &self.comment {
    //         data.extend(b" ");
    //         data.extend(comment);
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += 5;
        size += self.transaction_id.len();
        size += 3;
        if let Some(comment) = &self.comment {
            size += 1;
            size += comment.len()
        }
        size
    }
}

pub struct MsrpResponseLineReader<'a> {
    transaction_id: &'a [u8],
    status_code: String,
    comment: Option<&'a [u8]>,
    pos: usize,
}

impl<'a> Read for MsrpResponseLineReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < 5 && i < buf.len() {
            buf[i] = b"MSRP "[self.pos + i];
            i += 1;
        }
        while self.pos + i >= 5 && self.pos + i < 5 + self.transaction_id.len() && i < buf.len() {
            buf[i] = self.transaction_id[self.pos + i - 5];
            i += 1;
        }
        while self.pos + i >= 5 + self.transaction_id.len()
            && self.pos + i < 5 + self.transaction_id.len() + 1
            && i < buf.len()
        {
            buf[i] = b' ';
            i += 1;
        }
        while self.pos + i >= 5 + self.transaction_id.len() + 1
            && self.pos + i < 5 + self.transaction_id.len() + 1 + self.status_code.as_bytes().len()
            && i < buf.len()
        {
            buf[i] = self.status_code.as_bytes()[self.pos + i - 5 - self.transaction_id.len() - 1];
            i += 1;
        }
        if let Some(comment) = self.comment {
            while self.pos + i
                >= 5 + self.transaction_id.len() + 1 + self.status_code.as_bytes().len()
                && self.pos + i
                    < 5 + self.transaction_id.len() + 1 + self.status_code.as_bytes().len() + 1
                && i < buf.len()
            {
                buf[i] = b' ';
                i += 1;
            }
            while self.pos + i
                >= 5 + self.transaction_id.len() + 1 + self.status_code.as_bytes().len() + 1
                && self.pos + i
                    < 5 + self.transaction_id.len()
                        + 1
                        + self.status_code.as_bytes().len()
                        + 1
                        + comment.len()
                && i < buf.len()
            {
                buf[i] = comment[self.pos + i
                    - 5
                    - self.transaction_id.len()
                    - 1
                    - self.status_code.as_bytes().len()
                    - 1];
                i += 1;
            }
        }
        self.pos += i;
        Ok(i)
    }
}

pub enum ReportSuccess {
    Yes, // MUST send a success report or reports covering all bytes that are received successfully.
    No,  // MUST NOT send a success report
}

pub enum ReportFailure {
    Yes,     // observe for error transaction response and Failure-Reports in 30 seconds
    Partial, // MUST NOT send a 200 transaction response but SHOULD send an appropriate non-200 class response if a failure occurs.
    No,      // MUST NOT send a failure REPORT and MUST NOT send a transaction response.
}

pub struct MsrpChunkInfo<'a> {
    pub from_path: &'a [u8],
    pub to_path: &'a [u8],
    pub message_id: Option<&'a [u8]>,
    pub byte_range: Option<&'a [u8]>,
    pub content_type: Option<&'a [u8]>,
    pub success_report: Option<ReportSuccess>,
    pub failure_report: Option<ReportFailure>,
}

pub struct MsrpReportInfo<'a> {
    pub message_id: &'a [u8],
    pub ns: u16,
    pub status_code: u16,
    pub comment: Option<&'a [u8]>,
    pub byte_range: Option<&'a [u8]>,
}

pub enum MsrpChunk {
    Request(
        MsrpRequestLine,
        Vec<Header>,
        Option<Vec<u8>>,
        ContinuationFlag,
    ),
    Response(MsrpResponseLine, Vec<Header>),
}

impl MsrpChunk {
    pub fn new_request_chunk(
        req_line: MsrpRequestLine,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
        continuation_flag: ContinuationFlag,
    ) -> MsrpChunk {
        MsrpChunk::Request(req_line, headers, body, continuation_flag)
    }

    pub fn new_response_chunk(resp_line: MsrpResponseLine, headers: Vec<Header>) -> MsrpChunk {
        MsrpChunk::Response(resp_line, headers)
    }

    pub fn headers(&self) -> &[Header] {
        match self {
            MsrpChunk::Request(_, headers, _, _) => headers,
            MsrpChunk::Response(_, headers) => headers,
        }
    }

    pub fn add_header(&mut self, header: Header) {
        match self {
            MsrpChunk::Request(_, headers, _, _) => {
                headers.push(header);
            }
            MsrpChunk::Response(_, headers) => {
                headers.push(header);
            }
        }
    }

    pub fn set_body(&mut self, b: Option<Vec<u8>>) {
        match self {
            MsrpChunk::Request(_, _, body, _) => {
                *body = b;
            }
            _ => {}
        }
    }

    pub fn get_body(&self) -> Option<&Vec<u8>> {
        match self {
            MsrpChunk::Request(_, _, body, _) => {
                if let Some(body) = body {
                    Some(&body)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn get_chunk_info(&self) -> Option<MsrpChunkInfo> {
        let headers = self.headers();
        let from_path = header::search(headers, b"From-Path", false);
        let to_path = header::search(headers, b"To-Path", false);
        if let (Some(from_path), Some(to_path)) = (from_path, to_path) {
            let mut message_id_ = None;
            if let Some(message_id) = header::search(headers, b"Message-ID", false) {
                message_id_ = Some(message_id.get_value());
            }

            let mut byte_range_ = None;
            if let Some(byte_range) = header::search(headers, b"Byte-Range", false) {
                byte_range_ = Some(byte_range.get_value());
            }

            let mut content_type_ = None;
            if let Some(content_type) = header::search(headers, b"Content-Type", false) {
                content_type_ = Some(content_type.get_value());
            }

            let mut success_report_ = None;
            if let Some(success_report) = header::search(headers, b"Success-Report", false) {
                if success_report.get_value() == b"yes" {
                    success_report_.replace(ReportSuccess::Yes);
                }
                if success_report.get_value() == b"no" {
                    success_report_.replace(ReportSuccess::No);
                }
            }

            let mut failure_report_ = None;
            if let Some(failure_report) = header::search(headers, b"Failure-Report", false) {
                if failure_report.get_value() == b"yes" {
                    failure_report_.replace(ReportFailure::Yes);
                }
                if failure_report.get_value() == b"partial" {
                    failure_report_.replace(ReportFailure::Partial);
                }
                if failure_report.get_value() == b"no" {
                    failure_report_.replace(ReportFailure::No);
                }
            }

            match self {
                MsrpChunk::Request(req_line, _, _, _) => {
                    if req_line.request_method == b"SEND" {
                        if success_report_.is_none() {
                            success_report_.replace(ReportSuccess::No);
                        }
                        if failure_report_.is_none() {
                            failure_report_.replace(ReportFailure::Yes);
                        }
                    }
                }
                _ => {}
            }

            if failure_report_.is_none() {}

            return Some(MsrpChunkInfo {
                from_path: from_path.get_value(),
                to_path: to_path.get_value(),
                message_id: message_id_,
                byte_range: byte_range_,
                content_type: content_type_,
                success_report: success_report_,
                failure_report: failure_report_,
            });
        }

        None
    }

    pub fn get_report_status(&self) -> Option<MsrpReportInfo> {
        match self {
            MsrpChunk::Request(req_line, headers, _, _) => {
                if req_line.request_method == b"REPORT" {
                    if let Some(message_id_header) = header::search(headers, b"Message-ID", false) {
                        if let Some(status_header) = header::search(headers, b"Status", false) {
                            if let Some(status) = status_header.get_value().as_msrp_status() {
                                if status.ns == 0 && status.status_code == 200 {
                                    if let Some(byte_range) =
                                        header::search(headers, b"Byte-Range", false)
                                    {
                                        return Some(MsrpReportInfo {
                                            message_id: message_id_header.get_value(),
                                            ns: status.ns,
                                            status_code: status.status_code,
                                            comment: status.comment,
                                            byte_range: Some(byte_range.get_value()),
                                        });
                                    }
                                } else {
                                    return Some(MsrpReportInfo {
                                        message_id: message_id_header.get_value(),
                                        ns: status.ns,
                                        status_code: status.status_code,
                                        comment: status.comment,
                                        byte_range: None,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }

    pub fn get_data(&self) -> Option<&[u8]> {
        if let MsrpChunk::Request(_, _, data, _) = self {
            if let Some(data) = data {
                return Some(&data);
            }
        }
        None
    }

    pub fn get_readers<'a>(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        match &self {
            MsrpChunk::Request(req_line, headers, body, continuation_flag) => {
                readers.push(Box::new(req_line.reader()));
                readers.push(Box::new(&b"\r\n"[..]));
                headers_get_readers(headers, readers);
                if let Some(body) = body {
                    readers.push(Box::new(&body[..]));
                }
                readers.push(Box::new(&b"-------"[..]));
                readers.push(Box::new(&req_line.transaction_id[..]));
                match continuation_flag {
                    ContinuationFlag::Complete => {
                        readers.push(Box::new(&b"$\r\n"[..]));
                    }
                    ContinuationFlag::Abort => {
                        readers.push(Box::new(&b"#\r\n"[..]));
                    }
                    ContinuationFlag::Continuation => {
                        readers.push(Box::new(&b"+\r\n"[..]));
                    }
                }
            }

            MsrpChunk::Response(resp_line, headers) => {
                readers.push(Box::new(resp_line.reader()));
                readers.push(Box::new(&b"\r\n"[..]));
                headers_get_readers(headers, readers);
                readers.push(Box::new(&b"-------"[..]));
                readers.push(Box::new(&resp_line.transaction_id[..]));
                readers.push(Box::new(&b"$\r\n"[..]));
            }
        }
    }
}

impl Serializable for MsrpChunk {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     match &self {
    //         MsrpChunk::Request(req_line, headers, body, continuation_flag) => {
    //             data.extend(req_line.serialize());
    //             data.extend(b"\r\n");
    //             data.extend(headers.serialize());
    //             if let Some(body) = body {
    //                 data.extend(b"\r\n");
    //                 data.extend(body);
    //             }
    //             data.extend(b"-------");
    //             data.extend(&req_line.transaction_id);
    //             match continuation_flag {
    //                 ContinuationFlag::Complete => {
    //                     data.extend(b"$\r\n");
    //                 }
    //                 ContinuationFlag::Abort => {
    //                     data.extend(b"#\r\n");
    //                 }
    //                 ContinuationFlag::Continuation => {
    //                     data.extend(b"+\r\n");
    //                 }
    //             }
    //         }
    //         MsrpChunk::Response(resp_line, headers) => {
    //             data.extend(resp_line.serialize());
    //             data.extend(b"\r\n");
    //             data.extend(headers.serialize());
    //             data.extend(b"-------");
    //             data.extend(&resp_line.transaction_id);
    //             data.extend(b"$\r\n");
    //         }
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        match &self {
            MsrpChunk::Request(req_line, headers, body, continuation_flag) => {
                size += req_line.estimated_size();
                size += 2;
                size += headers.estimated_size();
                if let Some(body) = body {
                    size += 2;
                    size += body.len();
                }
                size += 7;
                size += req_line.transaction_id.len();
                match continuation_flag {
                    ContinuationFlag::Complete => {
                        size += 3;
                    }
                    ContinuationFlag::Abort => {
                        size += 3;
                    }
                    ContinuationFlag::Continuation => {
                        size += 3;
                    }
                }
            }
            MsrpChunk::Response(resp_line, headers) => {
                size += resp_line.estimated_size();
                size += 2;
                size += headers.estimated_size();
                size += 7;
                size += resp_line.transaction_id.len();
                size += 3;
            }
        }
        size
    }
}
