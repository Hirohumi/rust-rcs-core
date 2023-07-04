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
use std::sync::Arc;

use crate::ffi::log::platform_log;
use crate::internet::body::Body;
use crate::internet::body::BodySerializationError;
use crate::internet::header;
use crate::internet::header::headers_get_readers;
use crate::internet::header::Header;
use crate::internet::header_field::AsHeaderField;
use crate::internet::header_field::HeaderField;

use crate::io::DynamicChain;
use crate::io::Serializable;

use crate::sip::sip_dialog::GetDialogHeaders;
use crate::sip::sip_headers::cseq::AsCSeq;

use crate::util::raw_string::ToInt;

const SIP2_0_BYTES: &[u8] = b"SIP/2.0";

pub const ACK: &[u8] = b"ACK";
pub const BYE: &[u8] = b"BYE";
pub const CANCEL: &[u8] = b"CANCEL";
pub const INVITE: &[u8] = b"INVITE";
pub const MESSAGE: &[u8] = b"MESSAGE";
pub const NOTIFY: &[u8] = b"NOTIFY";
pub const OPTIONS: &[u8] = b"OPTIONS";
pub const REFER: &[u8] = b"REFER";
pub const REGISTER: &[u8] = b"REGISTER";
pub const SUBSCRIBE: &[u8] = b"SUBSCRIBE";
pub const UPDATE: &[u8] = b"UPDATE";

const LOG_TAG: &str = "sip_message";

pub enum SipVersion {
    V2_0,
}

impl ToString for SipVersion {
    fn to_string(&self) -> String {
        match self {
            SipVersion::V2_0 => return String::from("SIP/2.0"),
        }
    }
}

impl fmt::Debug for SipVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SIP/2.0")
    }
}

pub struct SipRequestLine {
    pub method: Vec<u8>,
    pub uri: Vec<u8>,
    pub version: SipVersion,
}

impl SipRequestLine {
    pub fn reader(&self) -> SipRequestLineReader {
        SipRequestLineReader {
            method: &self.method,
            uri: &self.uri,
            version: match self.version {
                SipVersion::V2_0 => SipVersion::V2_0,
            },
            pos: 0,
        }
    }
}

impl Serializable for SipRequestLine {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     data.extend(&self.method);
    //     data.extend(b" ");
    //     data.extend(&self.uri);
    //     match &self.version {
    //         SipVersion::V2_0 => {
    //             data.extend(b" SIP/2.0");
    //         }
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.method.len();
        size += 1;
        size += self.uri.len();
        match &self.version {
            SipVersion::V2_0 => {
                size += 8;
            }
        }
        size
    }
}

impl fmt::Debug for SipRequestLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            String::from_utf8_lossy(&self.method),
            String::from_utf8_lossy(&self.uri),
            self.version.to_string()
        )
    }
}

pub struct SipRequestLineReader<'a> {
    method: &'a [u8],
    uri: &'a [u8],
    version: SipVersion,
    pos: usize,
}

impl<'a> Read for SipRequestLineReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < self.method.len() && i < buf.len() {
            buf[i] = self.method[self.pos + i];
            i += 1;
        }
        while self.pos + i >= self.method.len()
            && self.pos + i < self.method.len() + 1
            && i < buf.len()
        {
            buf[i] = b' ';
            i += 1;
        }
        while self.pos + i >= self.method.len() + 1
            && self.pos + i < self.method.len() + 1 + self.uri.len()
            && i < buf.len()
        {
            buf[i] = self.uri[self.pos + i - self.method.len() - 1];
            i += 1;
        }
        match self.version {
            SipVersion::V2_0 => {
                while self.pos + i >= self.method.len() + 1 + self.uri.len()
                    && self.pos + i < self.method.len() + 1 + self.uri.len() + 8
                    && i < buf.len()
                {
                    buf[i] = b" SIP/2.0"[self.pos + i - self.method.len() - 1 - self.uri.len()];
                    i += 1;
                }
            }
        }
        self.pos += i;
        Ok(i)
    }
}

pub struct SipResponseLine {
    pub version: SipVersion,
    pub status_code: u16,
    pub reason_phrase: Vec<u8>,
}

impl SipResponseLine {
    pub fn reader(&self) -> SipResponseLineReader {
        SipResponseLineReader {
            version: match self.version {
                SipVersion::V2_0 => SipVersion::V2_0,
            },
            status_code: format!("{:0>3}", self.status_code),
            reason_phrase: &self.reason_phrase,
            pos: 0,
        }
    }
}

impl Serializable for SipResponseLine {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::new();
    //     match self.version {
    //         SipVersion::V2_0 => {
    //             data.extend(b"SIP/2.0 ");
    //         }
    //     }
    //     data.extend(self.status_code.to_string().bytes());
    //     data.extend(b" ");
    //     data.extend(&self.reason_phrase);
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        match self.version {
            SipVersion::V2_0 => {
                size += 8;
            }
        }
        size += self.status_code.to_string().len();
        size += 1;
        size += self.reason_phrase.len();
        size
    }
}

impl fmt::Debug for SipResponseLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.version.to_string(),
            self.status_code,
            String::from_utf8_lossy(&self.reason_phrase)
        )
    }
}

pub struct SipResponseLineReader<'a> {
    version: SipVersion,
    status_code: String,
    reason_phrase: &'a [u8],
    pos: usize,
}

impl<'a> Read for SipResponseLineReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        let version_length;
        match self.version {
            SipVersion::V2_0 => {
                version_length = 8;
                while self.pos + i < 8 && i < buf.len() {
                    buf[i] = b"SIP/2.0 "[self.pos + i];
                    i += 1;
                }
            }
        }
        while self.pos + i >= version_length
            && self.pos + i < version_length + self.status_code.as_bytes().len()
            && i < buf.len()
        {
            buf[i] = self.status_code.as_bytes()[self.pos + i - version_length];
            i += 1;
        }
        while self.pos + i >= version_length + self.status_code.as_bytes().len()
            && self.pos + i < version_length + self.status_code.as_bytes().len() + 1
            && i < buf.len()
        {
            buf[i] = b' ';
            i += 1;
        }
        while self.pos + i >= version_length + self.status_code.as_bytes().len() + 1
            && self.pos + i
                < version_length + self.status_code.as_bytes().len() + 1 + self.reason_phrase.len()
            && i < buf.len()
        {
            buf[i] = self.reason_phrase
                [self.pos + i - version_length - self.status_code.as_bytes().len() - 1];
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}

pub enum SipFirstLine {
    Request(SipRequestLine),
    Response(SipResponseLine),
}

impl SipFirstLine {
    pub fn decode_first_line(s: &[u8]) -> Result<Option<(SipFirstLine, usize)>, &str> {
        let mut iter = s.iter();

        if let Some(position) = iter.position(|c| *c == b'\r') {
            if let Some(c) = iter.next() {
                if *c == b'\n' {
                    let mut iter = s[..position].splitn(3, |c| *c == b' ');

                    if let Some(s1) = iter.next() {
                        if let Some(s2) = iter.next() {
                            if let Some(s3) = iter.next() {
                                if s1 == SIP2_0_BYTES {
                                    if let Ok(status_code) = s2.to_int() {
                                        return Ok(Some((
                                            SipFirstLine::Response(SipResponseLine {
                                                version: SipVersion::V2_0,
                                                status_code,
                                                reason_phrase: s3.to_vec(),
                                            }),
                                            s1.len() + 1 + s2.len() + 1 + s3.len() + 2,
                                        )));
                                    } else {
                                        return Err("invalid status code");
                                    }
                                } else if s3 == SIP2_0_BYTES {
                                    return Ok(Some((
                                        SipFirstLine::Request(SipRequestLine {
                                            method: s1.to_vec(),
                                            uri: s2.to_vec(),
                                            version: SipVersion::V2_0,
                                        }),
                                        s1.len() + 1 + s2.len() + 1 + s3.len() + 2,
                                    )));
                                } else {
                                    return Err("unknown sip version");
                                }
                            }
                        }
                    }
                } else {
                    return Err("bad format");
                }
            }
        }

        Ok(None)
    }
}

pub enum SipMessage {
    Request(SipRequestLine, Option<Vec<Header>>, Option<Arc<Body>>),
    Response(SipResponseLine, Option<Vec<Header>>, Option<Arc<Body>>),
    Ping,
    Pong,
}

impl SipMessage {
    pub fn new(
        first_line: SipFirstLine,
        headers: Option<Vec<Header>>,
        body: Option<Arc<Body>>,
    ) -> SipMessage {
        match first_line {
            SipFirstLine::Request(line) => SipMessage::Request(line, headers, body),
            SipFirstLine::Response(line) => SipMessage::Response(line, headers, body),
        }
    }

    pub fn new_request(method: &[u8], uri: &[u8]) -> SipMessage {
        SipMessage::Request(
            SipRequestLine {
                method: method.to_vec(),
                uri: uri.to_vec(),
                version: SipVersion::V2_0,
            },
            None,
            None,
        )
    }

    pub fn new_response(status_code: u16, reason_phrase: &[u8]) -> SipMessage {
        SipMessage::Response(
            SipResponseLine {
                version: SipVersion::V2_0,
                status_code,
                reason_phrase: reason_phrase.to_vec(),
            },
            None,
            None,
        )
    }

    pub fn headers(&self) -> Option<&[Header]> {
        match self {
            SipMessage::Request(_, headers, _) => {
                if let Some(headers) = headers {
                    return Some(&*headers);
                }
            }
            SipMessage::Response(_, headers, _) => {
                if let Some(headers) = headers {
                    return Some(&*headers);
                }
            }
            _ => {}
        }

        None
    }

    pub fn copy_headers(&self) -> Vec<Header> {
        match self {
            SipMessage::Request(_, headers, _) => {
                if let Some(headers) = headers {
                    return headers.clone();
                }
            }
            SipMessage::Response(_, headers, _) => {
                if let Some(headers) = headers {
                    return headers.clone();
                }
            }
            _ => {}
        }

        Vec::new()
    }

    pub fn add_header(&mut self, header: Header) {
        match self {
            SipMessage::Request(_, headers, _) => match headers {
                Some(headers) => {
                    headers.push(header);
                }
                None => {
                    let mut v = Vec::new();
                    v.push(header);
                    headers.replace(v);
                }
            },
            SipMessage::Response(_, headers, _) => match headers {
                Some(headers) => {
                    headers.push(header);
                }
                None => {
                    let mut v = Vec::new();
                    v.push(header);
                    headers.replace(v);
                }
            },
            _ => {}
        }
    }

    pub fn add_header_at_front(&mut self, header: Header) {
        match self {
            SipMessage::Request(_, headers, _) => match headers {
                Some(headers) => {
                    let mut new_headers = Vec::new();
                    new_headers.push(header);
                    new_headers.append(headers);
                    *headers = new_headers;
                }
                None => {
                    let mut v = Vec::new();
                    v.push(header);
                    headers.replace(v);
                }
            },
            SipMessage::Response(_, headers, _) => match headers {
                Some(headers) => {
                    let mut new_headers = Vec::new();
                    new_headers.push(header);
                    new_headers.append(headers);
                    *headers = new_headers;
                }
                None => {
                    let mut v = Vec::new();
                    v.push(header);
                    headers.replace(v);
                }
            },
            _ => {}
        }
    }

    pub fn set_body(&mut self, b: Arc<Body>) {
        match self {
            SipMessage::Request(_, _, body) => {
                body.replace(b);
            }
            SipMessage::Response(_, _, body) => {
                body.replace(b);
            }
            _ => {}
        }
    }

    pub fn get_body(&self) -> Option<Arc<Body>> {
        match self {
            SipMessage::Request(_, _, body) | SipMessage::Response(_, _, body) => {
                if let Some(body) = body {
                    Some(Arc::clone(body))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn has_body(&self) -> bool {
        match self {
            SipMessage::Request(_, _, body) | SipMessage::Response(_, _, body) => body.is_some(),
            _ => false,
        }
    }

    pub fn get_readers<'a>(
        &'a self,
        readers: &mut Vec<Box<dyn Read + Send + 'a>>,
    ) -> Result<(), BodySerializationError> {
        match &self {
            SipMessage::Request(line, headers, body) => {
                readers.push(Box::new(line.reader()));
                readers.push(Box::new(&b"\r\n"[..]));
                if let Some(headers) = headers {
                    headers_get_readers(headers, readers);
                }
                readers.push(Box::new(&b"\r\n"[..]));
                if let Some(body) = body {
                    readers.push(Box::new(body.reader()?));
                }
            }
            SipMessage::Response(line, headers, body) => {
                readers.push(Box::new(line.reader()));
                readers.push(Box::new(&b"\r\n"[..]));
                if let Some(headers) = headers {
                    headers_get_readers(headers, readers);
                }
                readers.push(Box::new(&b"\r\n"[..]));
                if let Some(body) = body {
                    readers.push(Box::new(body.reader()?));
                }
            }
            SipMessage::Ping => {
                readers.push(Box::new(&b"\r\n\r\n"[..]));
            }
            SipMessage::Pong => {
                readers.push(Box::new(&b"\r\n"[..]));
            }
        }

        Ok(())
    }
}

impl fmt::Debug for SipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipMessage::Request(req_line, headers, body) => f
                .debug_tuple("SipMessage")
                .field(req_line)
                .field(headers)
                .field(body)
                .finish(),
            SipMessage::Response(resp_line, headers, body) => f
                .debug_tuple("SipMessage")
                .field(resp_line)
                .field(headers)
                .field(body)
                .finish(),
            SipMessage::Ping => write!(f, "Ping"),
            SipMessage::Pong => write!(f, "Pong"),
        }
    }
}

impl fmt::Display for SipMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Serializable for SipMessage {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::with_capacity(self.estimated_size());
    //     match &self {
    //         SipMessage::Request(line, headers, body) => {
    //             data.extend(line.serialize());
    //             data.extend(b"\r\n");
    //             if let Some(headers) = headers {
    //                 data.extend(headers.serialize());
    //             }
    //             data.extend(b"\r\n");
    //             if let Some(body) = body {
    //                 data.extend(body.serialize());
    //             }
    //         }
    //         SipMessage::Response(line, headers, body) => {
    //             data.extend(line.serialize());
    //             data.extend(b"\r\n");
    //             if let Some(headers) = headers {
    //                 data.extend(headers.serialize());
    //             }
    //             data.extend(b"\r\n");
    //             if let Some(body) = body {
    //                 data.extend(body.serialize());
    //             }
    //         }
    //         SipMessage::Ping => {
    //             data.extend(b"\r\n\r\n");
    //         }
    //         SipMessage::Pong => {
    //             data.extend(b"\r\n");
    //         }
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        match &self {
            SipMessage::Request(line, headers, body) => {
                size += line.estimated_size();
                size += 2;
                if let Some(headers) = headers {
                    size += headers.estimated_size();
                }
                size += 2;
                if let Some(body) = body {
                    size += body.estimated_size();
                }
            }
            SipMessage::Response(line, headers, body) => {
                size += line.estimated_size();
                size += 2;
                if let Some(headers) = headers {
                    size += headers.estimated_size();
                }
                size += 2;
                if let Some(body) = body {
                    size += body.estimated_size();
                }
            }
            SipMessage::Ping => {
                size += 4;
            }
            SipMessage::Pong => {
                size += 2;
            }
        }
        size
    }
}

impl GetDialogHeaders for SipMessage {
    fn get_dialog_headers<'a>(&'a self) -> Option<(&'a Header, HeaderField<'a>, HeaderField<'a>)> {
        if let Some(headers) = self.headers() {
            if let (Some(call_id_header), Some(from_header), Some(to_header)) = (
                header::search(headers, b"Call-ID", true),
                header::search(headers, b"From", true),
                header::search(headers, b"To", true),
            ) {
                return Some((
                    call_id_header,
                    from_header.get_value().as_header_field(),
                    to_header.get_value().as_header_field(),
                ));
            }
        }

        None
    }
}

// to-do: via headers should be attached before send
pub fn corresponding_cancel(invite_message: &SipMessage) -> Result<SipMessage, &'static str> {
    match invite_message {
        SipMessage::Request(req_line, headers, _) => {
            if let Some(headers) = headers {
                let call_id_header = header::search(headers, b"Call-ID", true);
                let cseq_header = header::search(headers, b"CSeq", true);
                let from_header = header::search(headers, b"From", true);
                let to_header = header::search(headers, b"To", true);
                let via_header = header::search(headers, b"Via", true);

                if let (
                    Some(call_id_header),
                    Some(cseq_header),
                    Some(from_header),
                    Some(to_header),
                    Some(via_header),
                ) = (
                    call_id_header,
                    cseq_header,
                    from_header,
                    to_header,
                    via_header,
                ) {
                    let cseq_header_field = cseq_header.get_value().as_header_field();
                    let cseq = cseq_header_field.as_cseq();
                    if let Some(cseq) = cseq {
                        let mut message = SipMessage::new_request(CANCEL, &req_line.uri);

                        message.add_header(Header::new(
                            b"Call-ID",
                            call_id_header.get_value().to_vec(),
                        ));

                        let cseq = format!("{} CANCEL", cseq.seq);

                        message.add_header(Header::new(b"CSeq", cseq));

                        message.add_header(Header::new(b"From", from_header.get_value().to_vec()));

                        message.add_header(Header::new(b"To", to_header.get_value().to_vec()));

                        message.add_header(Header::new(b"Via", via_header.get_value().to_vec()));

                        return Ok(message);
                    }
                }
            }
        }

        _ => {}
    }

    Err("Missing information")
}

pub fn build_message_data(message: &SipMessage) -> Vec<u8> {
    platform_log(LOG_TAG, "calling sip_message->build_message_data()");

    let data_size = message.estimated_size();
    let mut data = Vec::with_capacity(data_size);
    {
        let mut readers = Vec::new();
        match message.get_readers(&mut readers) {
            Ok(_) => {
                match DynamicChain::new(readers).read_to_end(&mut data) {
                    Ok(_) => {}
                    Err(_) => {
                        platform_log(LOG_TAG, "build_message_data() read error");
                        // to-do: early failure
                    }
                }
            }
            Err(_) => {
                platform_log(LOG_TAG, "build_message_data() read error");
                // to-do: early failure
            }
        }
    }

    data
}
