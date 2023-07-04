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

use crate::{internet::AsHeaderField, util::raw_string::ToInt};

pub struct CacheControl {
    pub no_cache: bool,
    pub max_age: u32,
}

pub fn parse(s: &[u8]) -> CacheControl {
    let mut cc = CacheControl {
        no_cache: true,
        max_age: 0,
    };

    let header_field = s.as_header_field();
    let iter = header_field.get_parameter_iterator();

    for param in iter {
        if param.name.eq_ignore_ascii_case(b"no-cache") {
            cc.no_cache = true;
        } else if param.name.eq_ignore_ascii_case(b"max-age") {
            if let Some(max_age) = param.value {
                if let Ok(max_age) = max_age.to_int::<u32>() {
                    cc.max_age = max_age;
                }
            }
        }
    }

    cc
}
