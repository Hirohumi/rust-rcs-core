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

use crate::internet::header_field::HeaderField;
use crate::internet::name_addr::AsNameAddr;
use crate::internet::name_addr::NameAddr;
use crate::internet::syntax;
use crate::io::Serializable;

pub struct FromTo<'a> {
    pub addresses: Vec<NameAddr<'a>>, // to-do:
    pub tag: Option<&'a [u8]>,
}

impl<'a> FromTo<'a> {
    pub fn get_readers(&'a self, readers: &mut Vec<Box<dyn Read + Send + 'a>>) {
        let mut first = true;
        for address in &self.addresses {
            if first {
                first = false;
            } else {
                readers.push(Box::new(&b", "[..]));
            }
            address.get_readers(readers);
        }
        if let Some(tag) = self.tag {
            readers.push(Box::new(&b";tag="[..]));
            readers.push(Box::new(&tag[..]));
        }
    }
}

pub trait AsFromTo<'a> {
    type Target;
    fn as_from_to(&'a self) -> Self::Target;
}

impl<'a> AsFromTo<'a> for HeaderField<'a> {
    type Target = FromTo<'a>;
    fn as_from_to(&'a self) -> FromTo {
        let mut from_to = FromTo {
            addresses: self.value.as_name_addresses(),
            tag: None,
        };
        for parameter in self.get_parameter_iterator() {
            if parameter.name.eq_ignore_ascii_case(b"tag") {
                if let Some(value) = &parameter.value {
                    from_to.tag = Some(syntax::unquote(&value));
                }
            }
        }
        from_to
    }
}

impl<'a> Serializable for FromTo<'a> {
    // fn serialize(&self) -> Vec<u8> {
    //     let mut data = Vec::new();
    //     let mut first = true;
    //     for address in &self.addresses {
    //         if first {
    //             first = false;
    //         } else {
    //             data.extend(b", ")
    //         }
    //         let d = address.serialize();
    //         data.extend(d);
    //     }
    //     if let Some(tag) = self.tag {
    //         data.extend(b";");
    //         data.extend_from_slice(tag);
    //     }
    //     data
    // }

    fn estimated_size(&self) -> usize {
        let mut size = 0;
        let mut first = true;
        for address in &self.addresses {
            if first {
                first = false;
            } else {
                size += 2;
            }
            size += address.estimated_size();
        }
        if let Some(tag) = self.tag {
            size += 1;
            size += tag.len();
        }
        size
    }
}
