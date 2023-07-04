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

use crate::internet::header;
use crate::internet::header_field::AsHeaderField;
use crate::internet::header_field::HeaderField;
use crate::io::Serializable;
use crate::util::raw_string::ToInt;

use crate::sip::sip_message::SipMessage;

pub struct CSeq<'a> {
    pub seq: u32,
    pub method: &'a [u8],
}

impl<'a> CSeq<'a> {
    pub fn reader(&self) -> CSeqReader {
        CSeqReader {
            seq: self.seq.to_string(),
            method: self.method,
            pos: 0,
        }
    }
}

pub trait AsCSeq<'a> {
    type Target;
    fn as_cseq(&'a self) -> Option<Self::Target>;
}

impl<'a> AsCSeq<'a> for HeaderField<'a> {
    type Target = CSeq<'a>;
    fn as_cseq(&'a self) -> Option<CSeq> {
        let mut iter = self.value.iter();
        if let Some(position) = iter.position(|c| *c == b' ') {
            if let Ok(seq) = self.value[..position].to_int() {
                return Some(CSeq {
                    seq,
                    method: &self.value[position + 1..],
                });
            }
        }
        None
    }
}

impl<'a> Serializable for CSeq<'a> {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::new();
    //     data.extend(self.seq.to_string().bytes());
    //     data.extend(b" ");
    //     data.extend(self.method);
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        size += self.seq.to_string().len();
        size += 1;
        size += self.method.len();
        size
    }
}

pub fn get_message_seq(message: &SipMessage) -> Result<u32, &'static str> {
    if let Some(headers) = message.headers() {
        if let Some(cseq_header) = header::search(headers, b"CSeq", true) {
            let cseq_header_field = cseq_header.get_value().as_header_field();
            if let Some(cseq) = cseq_header_field.as_cseq() {
                return Ok(cseq.seq);
            }
        }
    }

    Err("Missing header")
}

pub struct CSeqReader<'a> {
    seq: String,
    method: &'a [u8],
    pos: usize,
}

impl<'a> Read for CSeqReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        while self.pos + i < self.seq.as_bytes().len() && i < buf.len() {
            buf[i] = self.seq.as_bytes()[self.pos + i];
            i += 1;
        }
        while self.pos + i >= self.seq.as_bytes().len()
            && self.pos + i < self.seq.as_bytes().len() + 1
            && i < buf.len()
        {
            buf[i] = b' ';
            i += 1;
        }
        while self.pos + i >= self.seq.as_bytes().len() + 1
            && self.pos + i < self.seq.as_bytes().len() + 1 + self.method.len()
            && i < buf.len()
        {
            buf[i] = self.method[self.pos + i - self.seq.as_bytes().len() - 1];
            i += 1;
        }
        self.pos += i;
        Ok(i)
    }
}
