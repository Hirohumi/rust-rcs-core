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

use crate::internet::header_field::HeaderField;
use crate::internet::syntax;
use crate::util::raw_string::StrEq;

pub struct Via<'a> {
    pub sent_protocol: &'a [u8],
    pub sent_by: &'a [u8],
    pub keep: bool,
    pub branch: Option<&'a [u8]>,
}

pub trait AsVia<'a> {
    type Target;
    fn as_via(&'a self) -> Option<Self::Target>;
}

impl<'a> AsVia<'a> for HeaderField<'a> {
    type Target = Via<'a>;
    fn as_via(&'a self) -> Option<Via> {
        let mut iter = self.value.iter();
        if let Some(position) = iter.position(|c| *c == b' ') {
            let mut via = Via {
                sent_protocol: &self.value[..position],
                sent_by: &self.value[position + 1..],
                keep: false,
                branch: None,
            };
            for parameter in self.get_parameter_iterator() {
                if parameter.name.equals_bytes(b"keep", true) {
                    via.keep = true;
                } else if parameter.name.equals_bytes(b"branch", true) {
                    if let Some(value) = &parameter.value {
                        via.branch = Some(syntax::unquote(&value));
                    }
                }
            }
            Some(via)
        } else {
            None
        }
    }
}
