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

use crate::{internet::HeaderField, util::raw_string::StrEq};

use super::auth_param::AuthParamParser;

pub struct ResponseAuth<'a> {
    pub qop: &'a [u8],
    pub cnonce: &'a [u8],
    pub nc: &'a [u8],
    pub auth: &'a [u8],
}

pub struct AuthenticationInfo<'a> {
    pub next_nonce: Option<&'a [u8]>,
    pub response_auth: Option<ResponseAuth<'a>>,
}

pub trait AsAuthenticationInfo<'a> {
    type Target;
    fn as_authentication_info(&'a self) -> Self::Target;
}

impl<'a> AsAuthenticationInfo<'a> for [u8] {
    type Target = AuthenticationInfo<'a>;
    fn as_authentication_info(&'a self) -> Self::Target {
        let mut authentication_info = AuthenticationInfo {
            next_nonce: None,
            response_auth: None,
        };
        let mut qop = None;
        let mut cnonce = None;
        let mut nc = None;
        let mut response_auth = None;
        let mut p = 0;
        while let Some((param, advance)) = self[p..].try_auth_param() {
            if param.name.equals_bytes(b"next_nonce", true) {
                authentication_info.next_nonce = Some(param.value);
            } else if param.name.equals_bytes(b"qop", true) {
                qop = Some(param.value);
            } else if param.name.equals_bytes(b"cnonce", true) {
                cnonce = Some(param.value);
            } else if param.name.equals_bytes(b"nc", true) {
                nc = Some(param.value);
            } else if param.name.equals_bytes(b"rspauth", true) {
                response_auth = Some(param.value);
            }
            p += advance;
        }
        if let (Some(qop), Some(cnonce), Some(nc), Some(response_auth)) =
            (qop, cnonce, nc, response_auth)
        {
            authentication_info.response_auth = Some(ResponseAuth {
                qop,
                cnonce,
                nc,
                auth: response_auth,
            });
        }
        authentication_info
    }
}
