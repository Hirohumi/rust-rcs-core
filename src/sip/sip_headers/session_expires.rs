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
// use crate::internet::parameter;

use crate::util::raw_string::ToInt;

pub struct SessionExpires<'a> {
    pub timeout: u32,
    pub refresher: Option<&'a [u8]>,
}

pub trait AsSessionExpires<'a> {
    type Target;
    fn as_session_expires(&'a self) -> Option<Self::Target>;
}

impl<'a> AsSessionExpires<'a> for HeaderField<'a> {
    type Target = SessionExpires<'a>;
    fn as_session_expires(&'a self) -> Option<SessionExpires> {
        if let Ok(timeout) = self.value.to_int() {
            for p in self.get_parameter_iterator() {
                if p.name == b"refresher" {
                    return Some(SessionExpires {
                        timeout,
                        refresher: p.value,
                    });
                }
            }
            // if let Some(parameters) = &self.parameters {
            //     if let Some(refresher) = parameter::search(parameters, b"refresher") {
            //         return Some(SessionExpires {
            //             timeout,
            //             refresher: refresher.value,
            //         });
            //     }
            // }

            return Some(SessionExpires {
                timeout,
                refresher: None,
            });
        }

        None
    }
}
