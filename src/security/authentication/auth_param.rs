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

use crate::internet::syntax;

pub struct AuthParam<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

pub trait AuthParamParser<'a> {
    type Target;
    fn try_auth_param(&'a self) -> Option<(Self::Target, usize)>;
}

impl<'a> AuthParamParser<'a> for [u8] {
    type Target = AuthParam<'a>;
    fn try_auth_param(&'a self) -> Option<(Self::Target, usize)> {
        let (chunk, mut advance) = if let Some(idx) = syntax::index_with_token_escaping(self, b',')
        {
            (&self[..idx], idx)
        } else {
            (self, self.len())
        };

        let chunk = syntax::trim(chunk);

        if let Some(idx) = chunk.iter().position(|c| *c == b'=') {
            let name = &chunk[..idx];
            let value = &chunk[idx + 1..];

            if advance + 1 < self.len() {
                advance += syntax::index_skipping_ows_and_obs_fold(&self[advance + 1..]);
                advance += 1;
            }

            Some((
                AuthParam {
                    name,
                    value: syntax::unquote(value),
                },
                advance,
            ))
        } else {
            None
        }
    }
}
