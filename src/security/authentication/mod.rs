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

pub mod auth_param;
pub mod authentication_info;
pub mod basic;
pub mod challenge;
pub mod digest;

use basic::BasicChallengeParams;
use challenge::ChallengeParser;
use digest::DigestChallengeParams;

pub enum AuthenticationMethod<'a> {
    Basic(BasicChallengeParams<'a>),
    Digest(DigestChallengeParams<'a>),
}

pub struct AuthenticationMethods<'a> {
    challenge_parser: ChallengeParser<'a>,
}

impl<'a> AuthenticationMethods<'a> {
    pub fn new(s: &'a [u8]) -> AuthenticationMethods<'_> {
        let challenge_parser = ChallengeParser::new(s);
        AuthenticationMethods { challenge_parser }
    }
}

impl<'a> Iterator for AuthenticationMethods<'a> {
    type Item = AuthenticationMethod<'a>;
    fn next(&mut self) -> Option<AuthenticationMethod<'a>> {
        while let Some(challenge) = self.challenge_parser.next() {
            match challenge.auth_scheme {
                b"Basic" => {
                    if let Some(basic_challenge) = BasicChallengeParams::from_challenge(challenge) {
                        return Some(AuthenticationMethod::Basic(basic_challenge));
                    }
                }

                b"Digest" => {
                    if let Some(digest_challenge) = DigestChallengeParams::from_challenge(challenge)
                    {
                        return Some(AuthenticationMethod::Digest(digest_challenge));
                    }
                }

                _ => {}
            }
        }

        None
    }
}
