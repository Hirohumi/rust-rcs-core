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

use crate::ffi::log::platform_log;
use crate::internet::parameter::ParameterParser;
use crate::internet::syntax;

use super::auth_param::AuthParamParser;

const LOG_TAG: &str = "auth";

const CHARSET_TOKEN_68: [u8; 68] = [
    b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n', b'o', b'p',
    b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z', b'A', b'B', b'C', b'D', b'E', b'F',
    b'G', b'H', b'I', b'J', b'K', b'L', b'M', b'N', b'O', b'P', b'Q', b'R', b'S', b'T', b'U', b'V',
    b'W', b'X', b'Y', b'Z', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'-', b'.',
    b'_', b'~', b'+', b'/',
];

pub struct Challenge<'a> {
    pub auth_scheme: &'a [u8],

    params: &'a [u8],
}

impl<'a> Challenge<'a> {
    pub fn get_params(&self) -> ParameterParser<'a> {
        ParameterParser::new(self.params, b',', true)
    }
}

enum State<'a> {
    ExpectingScheme,
    ExpectingTokenOrParam(&'a [u8], usize),
    ExpectingParamOrScheme(&'a [u8], usize),
}

/// Parse Http/Sip WWW-Authenticate response Challenge per RFC 7235
///
/// # Examples
///
/// ```
/// use rust_rcs_core::security::authentication::challenge::ChallengeParser;
///
/// let a = b"Newauth realm=\"apps\", type=1,\n                       title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"";
/// let mut parser = ChallengeParser::new(a);
///
/// let b = parser.next().unwrap();
/// assert_eq!(b.auth_scheme, b"Newauth");
///
/// let mut p = b.get_params();
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"realm");
/// assert_eq!(c.value.unwrap(), b"\"apps\"");
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"type");
/// assert_eq!(c.value.unwrap(), b"1");
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"title");
/// assert_eq!(c.value.unwrap(), b"\"Login to \\\"apps\\\"\"");
///
/// let b = parser.next().unwrap();
/// assert_eq!(b.auth_scheme, b"Basic");
///
/// let mut p = b.get_params();
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"realm");
/// assert_eq!(c.value.unwrap(), b"\"simple\"");
///
/// let a = b"Digest realm=\"example.com\", qop=\"auth\", algorithm=SHA-256, nonce=\"ce696741c46032ba0470d841551f3a8be8e0cc3e2591353bd6bc822436cc8615b56706342a90a3e13c2fd94debdc839000a8b50acb64612f998d93ce628605c1\"";
/// let mut parser = ChallengeParser::new(a);
///
/// let b = parser.next().unwrap();
/// assert_eq!(b.auth_scheme, b"Digest");
///
/// let mut p = b.get_params();
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"realm");
/// assert_eq!(c.value.unwrap(), b"\"example.com\"");
///
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"qop");
/// assert_eq!(c.value.unwrap(), b"\"auth\"");
///
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"algorithm");
/// assert_eq!(c.value.unwrap(), b"SHA-256");
///
/// let c = p.next().unwrap();
/// assert_eq!(c.name, b"nonce");
/// assert_eq!(c.value.unwrap(), b"\"ce696741c46032ba0470d841551f3a8be8e0cc3e2591353bd6bc822436cc8615b56706342a90a3e13c2fd94debdc839000a8b50acb64612f998d93ce628605c1\"");
///
/// let c = p.next().is_none();
/// assert_eq!(c, true);
///
/// let b = parser.next().is_none();
/// assert_eq!(b, true);
/// ```
pub struct ChallengeParser<'a> {
    state: State<'a>,
    pub s: &'a [u8],
    pub p: usize,
}

impl<'a> ChallengeParser<'a> {
    pub fn new(s: &'a [u8]) -> ChallengeParser<'a> {
        ChallengeParser {
            state: State::ExpectingScheme,
            s,
            p: 0,
        }
    }
}

impl<'a> Iterator for ChallengeParser<'a> {
    type Item = Challenge<'a>;
    fn next(&mut self) -> Option<Challenge<'a>> {
        if self.p < self.s.len() {
            loop {
                match self.state {
                    State::ExpectingScheme => {
                        let (scheme, advance) = if let Some(idx) =
                            syntax::index_with_token_escaping(&self.s[self.p..], b' ')
                        {
                            (&self.s[self.p..self.p + idx], idx)
                        } else {
                            (&self.s[self.p..], self.s.len() - self.p)
                        };

                        let scheme = syntax::trim(scheme);
                        if scheme.len() == 0 {
                            self.p = self.p + advance;
                        } else {
                            if self.p + advance + 1 < self.s.len() {
                                self.p = self.p
                                    + advance
                                    + syntax::index_skipping_ows_and_obs_fold(
                                        &self.s[self.p + advance + 1..],
                                    )
                                    + 1;

                                self.state = State::ExpectingTokenOrParam(scheme, self.p);
                            } else {
                                break;
                            }
                        }
                    }

                    State::ExpectingTokenOrParam(scheme, start_of_params) => {
                        let (chunk, advance) = if let Some(idx) =
                            syntax::index_with_token_escaping(&self.s[self.p..], b' ')
                        {
                            (&self.s[self.p..self.p + idx], idx)
                        } else {
                            (&self.s[self.p..], self.s.len() - self.p)
                        };

                        let chunk = syntax::trim(chunk);
                        let mut is_token = true;
                        for c in chunk {
                            if !CHARSET_TOKEN_68.contains(c) {
                                is_token = false;
                                break;
                            }
                        }

                        if is_token {
                            self.state = State::ExpectingScheme;

                            self.p = self.p
                                + advance
                                + syntax::index_skipping_ows_and_obs_fold(
                                    &self.s[self.p + advance + 1..],
                                )
                                + 1;

                            return Some(Challenge {
                                auth_scheme: scheme,
                                params: &self.s[start_of_params..self.p + advance],
                            });
                        } else {
                            if let Some((_, advance)) =
                                self.s[self.p..self.p + advance].try_auth_param()
                            {
                                if self.p + advance + 1 < self.s.len() {
                                    self.p = self.p
                                        + advance
                                        + syntax::index_skipping_ows_and_obs_fold(
                                            &self.s[self.p + advance + 1..],
                                        )
                                        + 1;
                                } else {
                                    self.p += advance;
                                }
                                self.state = State::ExpectingParamOrScheme(scheme, start_of_params);
                            } else {
                                platform_log(
                                    LOG_TAG,
                                    "neither token68 nor auth-param detected in challenge string",
                                );
                                break;
                            }
                        }
                    }

                    State::ExpectingParamOrScheme(scheme, start_of_params) => {
                        let (chunk, advance) = if let Some(idx) =
                            syntax::index_with_token_escaping(&self.s[self.p..], b' ')
                        {
                            (&self.s[self.p..self.p + idx], idx)
                        } else {
                            (&self.s[self.p..], self.s.len() - self.p)
                        };

                        if let Some((_, advance)) =
                            self.s[self.p..self.p + advance].try_auth_param()
                        {
                            if self.p + advance + 1 < self.s.len() {
                                self.p = self.p
                                    + advance
                                    + syntax::index_skipping_ows_and_obs_fold(
                                        &self.s[self.p + advance + 1..],
                                    )
                                    + 1;
                            } else {
                                self.p += advance;
                            }
                        } else {
                            let chunk = syntax::trim(chunk);

                            let challenge = Challenge {
                                auth_scheme: scheme,
                                params: &self.s[start_of_params..self.p],
                            };

                            if self.p + advance + 1 < self.s.len() {
                                self.p = self.p
                                    + advance
                                    + syntax::index_skipping_ows_and_obs_fold(
                                        &self.s[self.p + advance + 1..],
                                    )
                                    + 1;

                                self.state = State::ExpectingTokenOrParam(chunk, self.p);

                                return Some(challenge);
                            } else {
                                self.p = self.p + advance;

                                self.state = State::ExpectingTokenOrParam(chunk, self.p);

                                return Some(challenge);
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::ChallengeParser;

    #[test]
    fn test_decode() {
        let a = b"Newauth realm=\"apps\", type=1,\n                       title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\"";
        let mut parser = ChallengeParser::new(a);

        let b = parser.next().unwrap();
        assert_eq!(b.auth_scheme, b"Newauth");

        let mut p = b.get_params();
        let c = p.next().unwrap();
        assert_eq!(c.name, b"realm");
        assert_eq!(c.value.unwrap(), b"\"apps\"");
        let c = p.next().unwrap();
        assert_eq!(c.name, b"type");
        assert_eq!(c.value.unwrap(), b"1");
        let c = p.next().unwrap();
        assert_eq!(c.name, b"title");
        assert_eq!(c.value.unwrap(), b"\"Login to \\\"apps\\\"\"");

        let b = parser.next().unwrap();
        assert_eq!(b.auth_scheme, b"Basic");

        let mut p = b.get_params();
        let c = p.next().unwrap();
        assert_eq!(c.name, b"realm");
        assert_eq!(c.value.unwrap(), b"\"simple\"");

        let a = b"Digest realm=\"example.com\", qop=\"auth\", algorithm=SHA-256, nonce=\"ce696741c46032ba0470d841551f3a8be8e0cc3e2591353bd6bc822436cc8615b56706342a90a3e13c2fd94debdc839000a8b50acb64612f998d93ce628605c1\"";
        let mut parser = ChallengeParser::new(a);

        let b = parser.next().unwrap();
        assert_eq!(b.auth_scheme, b"Digest");

        let mut p = b.get_params();
        let c = p.next().unwrap();
        assert_eq!(c.name, b"realm");
        assert_eq!(c.value.unwrap(), b"\"example.com\"");

        let c = p.next().unwrap();
        assert_eq!(c.name, b"qop");
        assert_eq!(c.value.unwrap(), b"\"auth\"");

        let c = p.next().unwrap();
        assert_eq!(c.name, b"algorithm");
        assert_eq!(c.value.unwrap(), b"SHA-256");

        let c = p.next().unwrap();
        assert_eq!(c.name, b"nonce");
        assert_eq!(c.value.unwrap(), b"\"ce696741c46032ba0470d841551f3a8be8e0cc3e2591353bd6bc822436cc8615b56706342a90a3e13c2fd94debdc839000a8b50acb64612f998d93ce628605c1\"");

        let c = p.next().is_none();
        assert_eq!(c, true);

        let b = parser.next().is_none();
        assert_eq!(b, true);
    }
}
