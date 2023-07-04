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

pub struct Parameter<'a> {
    pub name: &'a [u8],
    pub value: Option<&'a [u8]>,
}

impl<'a> Parameter<'a> {
    pub fn reader(&self) -> ParameterReader {
        ParameterReader {
            n: self.name,
            v: self.value,
            d: b';',
            pos: 0,
        }
    }
}

impl<'a> From<&'a [u8]> for Parameter<'a> {
    /// Build a Parameter from string bytes
    ///
    /// # Examples
    ///
    /// ```
    /// let a = "key=value".as_bytes();
    /// let p = rust_rcs_core::internet::parameter::Parameter::from(a);
    /// assert_eq!(p.name, "key".as_bytes());
    /// if let Some(value) = p.value {
    ///     assert_eq!(value, "value".as_bytes());
    /// } else {
    ///     panic!("decode not successful\n");
    /// }
    /// ```
    fn from(s: &'a [u8]) -> Parameter {
        let mut iter = s.iter();

        if let Some(position) = iter.position(|c| *c == b'=') {
            return Parameter {
                name: &s[..position],
                value: Some(&s[position + 1..]),
            };
        }

        return Parameter {
            name: s,
            value: None,
        };
    }
}

pub struct ParameterParser<'a> {
    s: &'a [u8],
    d: u8,
    p: usize,
    ows: bool,
}

impl<'a> ParameterParser<'a> {
    pub fn new(s: &'a [u8], d: u8, ows: bool) -> ParameterParser<'a> {
        ParameterParser { s, d, p: 0, ows }
    }
}

impl<'a> Iterator for ParameterParser<'a> {
    type Item = Parameter<'a>;
    fn next(&mut self) -> Option<Parameter<'a>> {
        if self.p < self.s.len() {
            let chunk;
            let advance;
            if let Some(idx) = syntax::index_with_token_escaping(&self.s[self.p..], self.d) {
                chunk = &self.s[self.p..self.p + idx];
                advance = idx;
            } else {
                chunk = &self.s[self.p..];
                advance = self.s.len() - self.p;
            }

            let chunk = syntax::trim(chunk);

            if self.p + advance + 1 < self.s.len() {
                if self.ows {
                    self.p = self.p
                        + advance
                        + syntax::index_skipping_ows_and_obs_fold(&self.s[self.p + advance + 1..])
                        + 1;
                } else {
                    self.p = self.p + advance + 1;
                }
            } else {
                self.p = self.p + advance + 1;
            }

            return Some(Parameter::from(chunk));
        }

        None
    }
}

// #[deprecated]
// pub fn parse_parameters(s: &[u8], delimeter: u8) -> Vec<Parameter> {
//     let mut parameters = Vec::new();

//     let mut iter = s.split(|c| *c == delimeter);

//     loop {
//         match iter.next() {
//             Some(s) => {
//                 let p = Parameter::from(s);
//                 parameters.push(p);
//             }
//             None => break,
//         }
//     }

//     parameters
// }

// #[deprecated]
// pub fn search<'a>(parameters: &'a [Parameter], name: &[u8]) -> Option<&'a Parameter<'a>> {
//     if let Some(position) = parameters.iter().position(|p| p.name == name) {
//         return Some(&parameters[position]);
//     }
//     None
// }

pub struct ParameterReader<'a> {
    n: &'a [u8],
    v: Option<&'a [u8]>,
    d: u8,
    pos: usize,
}

impl<'a> Read for ParameterReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut i = 0;
        let n_length = self.n.len();
        while self.pos + i < 1 && i < buf.len() {
            buf[i] = self.d;
            i += 1;
        }
        while self.pos + i >= 1 && self.pos + i < 1 + n_length && i < buf.len() {
            buf[i] = self.n[self.pos + i - 1];
            i += 1;
        }
        if let Some(v) = self.v {
            let v_length = v.len();
            while self.pos + i >= 1 + n_length && self.pos + i < 1 + n_length + 1 && i < buf.len() {
                buf[i] = b'=';
                i += 1;
            }
            while self.pos + i >= 1 + n_length + 1
                && self.pos + i < 1 + n_length + 1 + v_length
                && i < buf.len()
            {
                buf[i] = v[self.pos + i - 1 - n_length - 1];
                i += 1;
            }
        }
        self.pos += i;
        Ok(i)
    }
}
