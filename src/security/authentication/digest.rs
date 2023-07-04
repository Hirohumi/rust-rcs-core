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

extern crate data_encoding;
extern crate md5;
extern crate ring;

use data_encoding::HEXLOWER;

use md5::{Digest, Md5};

use ring::digest;
use ring::digest::SHA256;

use crate::ffi::log::platform_log;
use crate::internet::syntax;

use super::challenge::Challenge;

const LOG_TAG: &str = "digest";

pub struct DigestChallengeParams<'a> {
    pub realm: &'a [u8],
    pub nonce: &'a [u8],
    pub algorithm: &'a [u8],

    pub domain: Option<&'a [u8]>,
    pub opaque: Option<&'a [u8]>,
    pub qop: Option<&'a [u8]>,
}

impl<'a> DigestChallengeParams<'a> {
    pub fn from_challenge(challenge: Challenge<'a>) -> Option<DigestChallengeParams<'a>> {
        let mut realm: Option<&'a [u8]> = None;
        let mut nonce: Option<&'a [u8]> = None;
        let mut algorithm: Option<&'a [u8]> = None;

        let mut domain: Option<&'a [u8]> = None;
        let mut opaque: Option<&'a [u8]> = None;
        let mut qop: Option<&'a [u8]> = None; // MANDATORY since rfc7616

        for param in challenge.get_params() {
            match param.name {
                b"realm" => {
                    realm = match param.value {
                        Some(v) => Some(syntax::unquote(v)),
                        None => None,
                    };
                }

                b"nonce" => {
                    nonce = match param.value {
                        Some(v) => Some(syntax::unquote(v)),
                        None => None,
                    };
                }

                b"algorithm" => {
                    algorithm = param.value;
                }

                b"domain" => {
                    domain = match param.value {
                        Some(v) => Some(syntax::unquote(v)),
                        None => None,
                    };
                }

                b"opaque" => {
                    opaque = match param.value {
                        Some(v) => Some(syntax::unquote(v)),
                        None => None,
                    };
                }

                b"qop" => {
                    qop = match param.value {
                        Some(v) => Some(syntax::unquote(v)),
                        None => None,
                    };
                }

                _ => {}
            }
        }

        if let (Some(realm), Some(nonce)) = (realm, nonce) {
            if let Some(algorithm) = algorithm {
                Some(DigestChallengeParams {
                    realm,
                    nonce,
                    algorithm,

                    domain,
                    opaque,
                    qop,
                })
            } else {
                Some(DigestChallengeParams {
                    realm,
                    nonce,
                    algorithm: b"MD5",

                    domain,
                    opaque,
                    qop,
                })
            }
        } else {
            None
        }
    }

    pub fn preferred_qop(&self, have_entity: bool) -> Option<&'a [u8]> {
        if let Some(qop) = self.qop {
            let mut auth: Option<&[u8]> = None;
            let mut auth_int: Option<&[u8]> = None;
            let mut iter = qop.split(|c| *c == b',');
            while let Some(qop) = iter.next() {
                if qop == b"auth" {
                    auth.replace(qop);
                } else if qop == b"auth-int" {
                    auth_int.replace(qop);
                }
            }

            if let Some(auth_int) = auth_int {
                if have_entity {
                    return Some(auth_int);
                }
            }

            if let Some(auth) = auth {
                return Some(auth);
            }

            if let Some(auth_int) = auth_int {
                return Some(auth_int);
            }
        }

        None
    }

    fn create_response(
        &self,
        username: &[u8],
        uri: &[u8],
        credentials: &DigestCredentials,
        hash_algorithm: &[u8],
    ) -> Result<(String, Option<&[u8]>), ErrorKind> {
        let mut hash_function = HashFunction::new(hash_algorithm)?;

        hash_function.update(username);
        hash_function.update(b":");
        hash_function.update(self.realm);
        hash_function.update(b":");
        hash_function.update(&credentials.password);

        let a1 = hash_function.finish();

        platform_log(LOG_TAG, format!("on intermediate result a1: {}", &a1));

        let mut hash_function = HashFunction::new(hash_algorithm)?;

        if let Some(method) = &credentials.client_data {
            hash_function.update(method);
        }

        hash_function.update(b":");
        hash_function.update(uri);

        let qop;

        if let Some(entity_digest) = &credentials.entity_digest {
            qop = self.preferred_qop(true);
            if let Some(b"auth-int") = qop {
                hash_function.update(b":");
                hash_function.update(entity_digest);
            }
        } else {
            qop = self.preferred_qop(false);
            if let Some(b"auth-int") = qop {
                hash_function.update(b":");
                let empty = empty_digest(hash_algorithm)?;
                hash_function.update(empty.as_bytes());
            }
        }

        let a2 = hash_function.finish();

        platform_log(LOG_TAG, format!("on intermediate result a2: {}", &a2));

        let mut hash_function = HashFunction::new(hash_algorithm)?;

        hash_function.update(a1.as_bytes());
        hash_function.update(b":");
        hash_function.update(self.nonce);
        hash_function.update(b":");

        match qop {
            Some(qop) => {
                if qop == b"auth" || qop == b"auth-int" {
                    if let Some((cnonce, nc)) = &credentials.client_nonce {
                        hash_function.update(format!("{:08x}", nc).as_bytes());
                        hash_function.update(b":");
                        hash_function.update(cnonce);
                        hash_function.update(b":");
                        hash_function.update(qop);
                        hash_function.update(b":");
                    } else {
                        return Err(ErrorKind::MissingInput);
                    }
                }
            }

            _ => {}
        }

        hash_function.update(a2.as_bytes());

        Ok((hash_function.finish(), qop))
    }

    pub fn to_challenge(&self) -> DigestChallenge {
        DigestChallenge {
            realm: self.realm.to_vec(),
            nonce: self.nonce.to_vec(),
            algorithm: self.algorithm.to_vec(),

            domain: match self.domain {
                Some(domain) => Some(domain.to_vec()),
                None => None,
            },

            opaque: match self.opaque {
                Some(opaque) => Some(opaque.to_vec()),
                None => None,
            },

            qop: match self.qop {
                Some(qop) => Some(qop.to_vec()),
                None => None,
            },
        }
    }
}

pub struct DigestChallenge {
    pub realm: Vec<u8>,
    pub nonce: Vec<u8>,
    pub algorithm: Vec<u8>,

    pub domain: Option<Vec<u8>>,
    pub opaque: Option<Vec<u8>>,
    pub qop: Option<Vec<u8>>,
}

impl DigestChallenge {
    pub fn as_challenge_param(&self) -> DigestChallengeParams {
        DigestChallengeParams {
            realm: &self.realm,
            nonce: &self.nonce,
            algorithm: &self.algorithm,

            domain: match &self.domain {
                Some(domain) => Some(&domain),
                None => None,
            },

            opaque: match &self.opaque {
                Some(opaque) => Some(&opaque),
                None => None,
            },

            qop: match &self.qop {
                Some(qop) => Some(&qop),
                None => None,
            },
        }
    }
}

pub struct DigestCredentials {
    pub password: Vec<u8>,

    pub client_data: Option<Vec<u8>>,
    pub client_nonce: Option<(Vec<u8>, u32)>,
    pub entity_digest: Option<Vec<u8>>,

    pub extra_params: Vec<(Vec<u8>, Vec<u8>)>,
}

// to-do: use referenced values
pub struct DigestAnswerParams {
    pub realm: Vec<u8>,
    pub algorithm: Option<Vec<u8>>,

    pub username: Vec<u8>,
    pub uri: Vec<u8>,

    pub challenge: Option<DigestChallenge>,

    pub credentials: Option<DigestCredentials>,
}

impl DigestAnswerParams {
    pub fn make_authorization_header(
        &self,
        hash_algorithm: Option<&[u8]>,
        with_empty_nonce: bool,
        with_empty_response: bool,
    ) -> Result<Vec<u8>, ErrorKind> {
        platform_log(LOG_TAG, format!("make authorization header with algorithm={} username={} password={} method={} realm={} uri={} qop={} nonce={} cnonce={} nc={}", if let Some(hash_algorithm) = &hash_algorithm{
            String::from_utf8_lossy(hash_algorithm)
        } else {
            std::borrow::Cow::Borrowed("")
        }, String::from_utf8_lossy(&self.username),
        if let Some(credentials) = &self.credentials {
            HEXLOWER.encode(&credentials.password)
        } else {
            String::from("")
        },
        if let Some(credentials) = &self.credentials {
            if let Some(client_data) = &credentials.client_data {
                String::from_utf8_lossy(client_data)
            } else {
                std::borrow::Cow::Borrowed("")
            }
        } else {
            std::borrow::Cow::Borrowed("")
        },
        if let Some(challenge) = &self.challenge {
            String::from_utf8_lossy(&challenge.realm)
        } else {
            String::from_utf8_lossy(&self.realm)
        },
        String::from_utf8_lossy(&self.uri),
        if let Some(challenge) = &self.challenge {
            let mut have_entity = false;
            if let Some(credentials) = &self.credentials {
                if let Some(_) = credentials.entity_digest {
                    have_entity = true;
                }
            }
            if let Some(qop) = challenge.as_challenge_param().preferred_qop(have_entity) {
                String::from_utf8_lossy(qop)
            } else {
                std::borrow::Cow::Borrowed("")
            }
        } else {
            std::borrow::Cow::Borrowed("")
        },
        if let Some(challenge) = &self.challenge {
            String::from_utf8_lossy(&challenge.nonce)
        } else {
            std::borrow::Cow::Borrowed("")
        },
        if let Some(credentials) = &self.credentials {
            if let Some((client_nonce, _)) = &credentials.client_nonce {
                String::from_utf8_lossy(client_nonce)
            } else {
                std::borrow::Cow::Borrowed("")
            }
        } else {
            std::borrow::Cow::Borrowed("")
        },
        if let Some(credentials) = &self.credentials {
            if let Some((_, nc)) = &credentials.client_nonce {
                format!("{}", nc)
            } else {
                String::from("")
            }
        } else {
            String::from("")
        },
    ));

        let mut v = Vec::new();

        v.extend_from_slice(b"Digest ");
        v.extend_from_slice(b"username=\"");
        v.extend_from_slice(&self.username);
        v.extend_from_slice(b"\"");
        if let Some(challenge) = &self.challenge {
            v.extend_from_slice(b",realm=\"");
            v.extend_from_slice(&challenge.realm);
            v.extend_from_slice(b"\"");
        } else {
            v.extend_from_slice(b",realm=\"");
            v.extend_from_slice(&self.realm);
            v.extend_from_slice(b"\"");
        }
        v.extend_from_slice(b",uri=\"");
        v.extend_from_slice(&self.uri);
        v.extend_from_slice(b"\"");

        if let Some(algorithm) = &self.algorithm {
            v.extend_from_slice(b",algorithm=");
            v.extend_from_slice(&algorithm);
        }

        if let Some(challenge) = &self.challenge {
            if let Some(domain) = &challenge.domain {
                v.extend_from_slice(b",domain=\"");
                v.extend_from_slice(&domain);
                v.extend_from_slice(b"\"");
            }

            let mut have_entity = false;
            if let Some(credentials) = &self.credentials {
                if let Some(_) = credentials.entity_digest {
                    have_entity = true;
                }
            }

            if let Some(qop) = challenge.as_challenge_param().preferred_qop(have_entity) {
                v.extend_from_slice(b",qop=");
                v.extend_from_slice(qop);
            }

            v.extend_from_slice(b",nonce=\"");
            v.extend_from_slice(&challenge.nonce);
            v.extend_from_slice(b"\"");
        } else {
            if with_empty_nonce {
                v.extend_from_slice(b",nonce=\"");
                v.extend_from_slice(b"");
                v.extend_from_slice(b"\"");
            }
        }

        let mut response_appended = false;

        if let Some(credentials) = &self.credentials {
            if let Some((cnonce, nc)) = &credentials.client_nonce {
                v.extend_from_slice(b",cnonce=\"");
                v.extend_from_slice(&cnonce);
                v.extend_from_slice(b"\",nc=");
                v.extend_from_slice(format!("{:08x}", nc).as_bytes());
            }

            if let (Some(challenge), Some(algorithm)) = (&self.challenge, hash_algorithm) {
                if let Ok((response, qop)) = challenge.as_challenge_param().create_response(
                    &self.username,
                    &self.uri,
                    &credentials,
                    algorithm,
                ) {
                    v.extend_from_slice(b",response=\"");
                    v.extend_from_slice(response.as_bytes());
                    v.extend_from_slice(b"\"");
                    response_appended = true;
                }
            }
        }

        if !response_appended && with_empty_response {
            v.extend_from_slice(b",response=\"");
            v.extend_from_slice(b"");
            v.extend_from_slice(b"\"");
        }

        if let Some(credentials) = &self.credentials {
            for (extra_param_name, extra_param_value) in &credentials.extra_params {
                v.extend_from_slice(b",");
                v.extend_from_slice(extra_param_name);
                v.extend_from_slice(b"=\"");
                v.extend_from_slice(extra_param_value);
                v.extend_from_slice(b"\"");
            }
        }

        if let Some(challenge) = &self.challenge {
            if let Some(opaque) = &challenge.opaque {
                v.extend_from_slice(b",opaque=\"");
                v.extend_from_slice(&opaque);
                v.extend_from_slice(b"\"");
            }
        }

        Ok(v)
    }
}

pub enum ErrorKind {
    MissingInput,
    NoSuchAlgorithm,
}

enum HashFunction {
    MD5(Md5),
    SHA256(digest::Context),
}

impl HashFunction {
    fn new(algorithm: &[u8]) -> Result<HashFunction, ErrorKind> {
        if algorithm.eq_ignore_ascii_case(b"md5") {
            Ok(HashFunction::MD5(Md5::new()))
        } else if algorithm.eq_ignore_ascii_case(b"sha256")
            || algorithm.eq_ignore_ascii_case(b"sha-256")
        {
            Ok(HashFunction::SHA256(digest::Context::new(&SHA256)))
        } else {
            Err(ErrorKind::NoSuchAlgorithm)
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            HashFunction::MD5(md5) => md5.update(data),

            HashFunction::SHA256(context) => context.update(data),
        }
    }

    fn finish(self) -> String {
        match self {
            HashFunction::MD5(md5) => HEXLOWER.encode(&md5.finalize()),

            HashFunction::SHA256(context) => HEXLOWER.encode(context.finish().as_ref()),
        }
    }
}

pub fn empty_digest(algorithm: &[u8]) -> Result<String, ErrorKind> {
    match algorithm {
        b"md5" => {
            let md5 = Md5::new();
            Ok(HEXLOWER.encode(&md5.finalize()))
        }

        b"sha256" | b"sha-256" => {
            let context = digest::Context::new(&SHA256);
            Ok(HEXLOWER.encode(context.finish().as_ref()))
        }

        _ => Err(ErrorKind::NoSuchAlgorithm),
    }
}
