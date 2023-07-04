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

use crate::util::raw_string::StrEq;

use super::super::header_field::HeaderField;
use super::super::syntax;

pub struct ContentType<'a> {
    pub major_type: &'a [u8],
    pub sub_type: &'a [u8],
    pub boundary: &'a [u8],
    pub charset: &'a [u8],
}

pub trait AsContentType<'a> {
    type Target;
    fn as_content_type(&'a self) -> Option<Self::Target>;
}

impl<'a> AsContentType<'a> for HeaderField<'a> {
    type Target = ContentType<'a>;
    fn as_content_type(&'a self) -> Option<ContentType> {
        let mut iter = self.value.iter();
        if let Some(position) = iter.position(|c| *c == b'/') {
            let mut content_type = ContentType {
                major_type: &self.value[..position],
                sub_type: &self.value[position + 1..],
                boundary: &[],
                charset: &[],
            };
            for parameter in self.get_parameter_iterator() {
                if parameter.name.equals_bytes(b"boundary", true) {
                    if let Some(value) = &parameter.value {
                        content_type.boundary = syntax::unquote(&value);
                    }
                } else if parameter.name.equals_bytes(b"charset", true) {
                    if let Some(value) = &parameter.value {
                        content_type.charset = syntax::unquote(&value);
                    }
                }
            }
            Some(content_type)
        } else {
            None
        }
    }
}
