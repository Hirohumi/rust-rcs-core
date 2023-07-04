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

pub mod aka;
pub mod authentication;
pub mod gba;

use std::sync::{Arc, Mutex};

use cached::{Cached, TimedSizedCache};

use crate::internet::{syntax, Header};
use crate::util::rand;

use self::authentication::authentication_info::AsAuthenticationInfo;
use self::{
    authentication::digest::{DigestAnswerParams, DigestChallenge, DigestCredentials},
    gba::{get_gba_realm, GbaContext},
};

pub struct CachedDigestParameter {
    pub algorithm: Vec<u8>,
    pub realm: Vec<u8>,
    pub uri: Vec<u8>,
    pub qop: Option<Vec<u8>>,
    pub next_nonce: Vec<u8>,
}

pub struct SecurityContext {
    cache: Arc<Mutex<TimedSizedCache<String, CachedDigestParameter>>>,
}

impl SecurityContext {
    pub fn new() -> SecurityContext {
        SecurityContext {
            cache: Arc::new(Mutex::new(
                TimedSizedCache::with_size_and_lifespan_and_refresh(32, 60 * 60, true),
            )),
        }
    }

    pub fn preload_auth(
        &self,
        gba_context: &Arc<GbaContext>,
        host: &str,
        cipher_id: Option<(u8, u8)>,
        method: &[u8],
        body_digest: Option<&[u8]>,
    ) -> Option<DigestAnswerParams> {
        if let Some(param) = self.cache.lock().unwrap().cache_get(host) {
            if let Some(_) = get_gba_realm(&param.realm) {
                if let Some(bootstrapped_context) = gba_context.try_get_bootstrapped_context() {
                    if let Ok(credential) =
                        bootstrapped_context.get_credential(host.as_bytes(), cipher_id)
                    {
                        let cnonce = rand::create_raw_alpha_numeric_string(16);
                        let nc = bootstrapped_context.increase_and_get_use_count();

                        let digest_answer = DigestAnswerParams {
                            realm: syntax::unquote(&param.realm).to_vec(),
                            algorithm: Some(param.algorithm.to_vec()),

                            username: credential.username,
                            uri: syntax::unquote(&param.uri).to_vec(),

                            challenge: Some(DigestChallenge {
                                realm: param.realm.to_vec(),
                                nonce: param.next_nonce.to_vec(),
                                algorithm: param.algorithm.to_vec(),
                                domain: None,
                                opaque: None,
                                qop: param.qop.clone(),
                            }),

                            credentials: Some(DigestCredentials {
                                password: credential.password,
                                client_data: Some(method.to_vec()),
                                client_nonce: Some((cnonce, nc)),
                                entity_digest: match body_digest {
                                    Some(body_digest) => Some(body_digest.to_vec()),
                                    None => None,
                                },
                                extra_params: Vec::new(),
                            }),
                        };

                        return Some(digest_answer);
                    }
                }
            }
        }

        None
    }

    pub fn update_auth_info(
        &self,
        authentication_info_header: &Header,
        host: &str,
        uri: &[u8],
        challenge: &DigestChallenge,
        have_entity: bool,
    ) {
        let authentication_info = authentication_info_header
            .get_value()
            .as_authentication_info();
        if let Some(next_nonce) = authentication_info.next_nonce {
            self.cache.lock().unwrap().cache_set(
                String::from(host),
                CachedDigestParameter {
                    algorithm: challenge.algorithm.to_vec(),
                    realm: challenge.realm.to_vec(),
                    uri: uri.to_vec(),
                    qop: match challenge.as_challenge_param().preferred_qop(have_entity) {
                        Some(qop) => Some(qop.to_vec()),
                        None => None,
                    },
                    next_nonce: next_nonce.to_vec(),
                },
            );
        }
    }
}
