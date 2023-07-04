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

use std::{str::FromStr, u8};

pub trait StrEq {
    fn equals_bytes(&self, b: &[u8], ignore_case: bool) -> bool;
    fn equals_string(&self, s: &str, ignore_case: bool) -> bool;
}

impl StrEq for [u8] {
    fn equals_bytes(&self, b: &[u8], ignore_case: bool) -> bool {
        if self.len() != b.len() {
            return false;
        }

        let mut i = 0;
        let mut rh_iter = b.iter();
        loop {
            if let Some(rhs) = rh_iter.next() {
                let lhs = self[i];
                if lhs == *rhs {
                    i = i + 1;
                    continue;
                }
                if ignore_case {
                    if lhs >= b'a' && lhs <= b'z' && *rhs == (lhs + b'A' - b'a')
                        || lhs >= b'A' && lhs <= b'Z' && *rhs == (lhs - b'A' + b'a')
                    {
                        i = i + 1;
                        continue;
                    }
                }
                return false;
            } else {
                return true;
            }
        }
    }

    fn equals_string(&self, s: &str, ignore_case: bool) -> bool {
        let b = s.as_bytes();
        <[u8]>::equals_bytes(self, b, ignore_case)
    }
}

impl StrEq for Vec<u8> {
    fn equals_bytes(&self, b: &[u8], ignore_case: bool) -> bool {
        <[u8]>::equals_bytes(self, b, ignore_case)
    }

    fn equals_string(&self, s: &str, ignore_case: bool) -> bool {
        <[u8]>::equals_string(self, s, ignore_case)
    }
}

pub trait StrFind {
    fn start_with(&self, s: &[u8]) -> bool;
    fn index_of(&self, s: &[u8]) -> Option<usize>;
}

impl StrFind for [u8] {
    fn start_with(&self, s: &[u8]) -> bool {
        if self.len() >= s.len() {
            let mut i = 0;
            while i < s.len() {
                if s[i] != self[i] {
                    return false;
                }
                i = i + 1;
            }
            return true;
        }

        false
    }

    fn index_of(&self, s: &[u8]) -> Option<usize> {
        let mut i = 0;

        while i + s.len() <= self.len() {
            let lhs = &self[i..i + s.len()];

            if lhs == s {
                return Some(i);
            }

            i = i + 1;
        }

        None
    }
}

impl StrFind for Vec<u8> {
    fn start_with(&self, s: &[u8]) -> bool {
        <[u8]>::start_with(self, s)
    }

    fn index_of(&self, s: &[u8]) -> Option<usize> {
        <[u8]>::index_of(self, s)
    }
}

pub trait ToInt {
    fn to_int<R>(&self) -> Result<R, String>
    where
        R: FromStr;
}

impl ToInt for [u8] {
    fn to_int<R>(&self) -> Result<R, String>
    where
        R: FromStr,
    {
        match std::str::from_utf8(self) {
            Ok(s) => match R::from_str(s) {
                Ok(i) => return Ok(i),
                Err(_) => {
                    return Err(String::from("std::num::ParseIntError"));
                }
            },
            Err(e) => {
                // std::str::Utf8Error
                let s: String = format!("{}", e);
                return Err(s);
            }
        }
    }
}

impl ToInt for Vec<u8> {
    fn to_int<R>(&self) -> Result<R, String>
    where
        R: FromStr,
    {
        <[u8]>::to_int(self)
    }
}

pub trait FromRawStr: Sized {
    type Err;
    fn from_raw_str(s: &[u8]) -> Result<Self, Self::Err>;
}
