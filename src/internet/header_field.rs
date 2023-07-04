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

use super::parameter::ParameterParser;
use super::syntax;

pub struct HeaderField<'a> {
    pub value: &'a [u8],
    pub parameters: &'a [u8],
}

impl HeaderField<'_> {
    pub fn get_parameter_iterator(&self) -> ParameterParser {
        ParameterParser::new(self.parameters, b';', false)
    }
}

pub trait AsHeaderField<'a> {
    type Target;
    fn as_header_field(&'a self) -> Self::Target;
}

impl<'a> AsHeaderField<'a> for [u8] {
    type Target = HeaderField<'a>;
    fn as_header_field(&'a self) -> HeaderField {
        if let Some(idx) = syntax::index_with_token_escaping(self, b';') {
            // let parameters = parameter::parse_parameters(self, b';');
            HeaderField {
                value: &self[..idx],
                parameters: &self[idx + 1..],
            }
        } else {
            HeaderField {
                value: self,
                parameters: &[],
            }
        }
    }
}

impl<'a> AsHeaderField<'a> for Vec<u8> {
    type Target = HeaderField<'a>;
    fn as_header_field(&'a self) -> HeaderField {
        <[u8]>::as_header_field(self)
    }
}
