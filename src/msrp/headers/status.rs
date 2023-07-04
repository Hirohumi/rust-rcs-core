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

use crate::util::raw_string::ToInt;

pub struct Status<'a> {
    pub ns: u16,
    pub status_code: u16,
    pub comment: Option<&'a [u8]>,
}

pub trait AsMsrpStatus<'a> {
    type Target;
    fn as_msrp_status(&'a self) -> Option<Self::Target>;
}

impl<'a> AsMsrpStatus<'a> for [u8] {
    type Target = Status<'a>;
    fn as_msrp_status(&'a self) -> Option<Status> {
        if self.len() > 3 && self[3] == b' ' {
            if self.len() == 7 || (self.len() > 7 && self[7] == b' ') {
                let i1 = &self[..3].to_int();
                let i2 = &self[4..7].to_int();
                if let (Ok(i1), Ok(i2)) = (i1, i2) {
                    if self.len() == 7 {
                        return Some(Status {
                            ns: *i1,
                            status_code: *i2,
                            comment: None,
                        });
                    } else {
                        return Some(Status {
                            ns: *i1,
                            status_code: *i2,
                            comment: Some(&self[8..]),
                        });
                    }
                }
            }
        }

        None
    }
}
