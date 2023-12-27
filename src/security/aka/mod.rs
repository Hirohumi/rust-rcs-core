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

extern crate base64;

use base64::{engine::general_purpose, Engine as _};
use data_encoding::HEXUPPER;
use libc::{c_int, c_void, size_t};

use crate::ffi::icc::IccChannel;

use crate::ffi::log::platform_log;
use crate::util::raw_string::{FromRawStr, StrFind};

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
const PLATFORM_SUPPORT_DIRECT_AKA: bool = true;

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
const PLATFORM_SUPPORT_DIRECT_AKA: bool = false;

const LOG_TAG: &str = "aka";

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" {
    fn platform_perform_aka(
        subscription_id: c_int,
        in_data: *const c_void,
        in_size: size_t,
        out_size: *mut size_t,
    ) -> *mut c_void;
}

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
fn perform_aka(challenge_data: &[u8], subscription_id: i32) -> Result<Vec<u8>, ErrorKind> {
    let mut out_size: size_t = 0;
    let out_data;

    unsafe {
        out_data = platform_perform_aka(
            subscription_id,
            challenge_data.as_ptr() as *const c_void,
            challenge_data.len(),
            &mut out_size,
        );

        if out_size <= 0 || out_data.is_null() {
            return Err(ErrorKind::FFI);
        }

        let mut data: Vec<u8> = Vec::with_capacity(out_size);

        std::ptr::copy_nonoverlapping(out_data as *const u8, data.as_mut_ptr(), out_size);

        libc::free(out_data);

        data.set_len(out_size);

        return Ok(data);
    }
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
fn perform_aka(challenge_data: &[u8], subscription_id: i32) -> Result<Vec<u8>, ErrorKind> {
    Err(ErrorKind::FFI)
}

pub struct AkaAlgorithm<'a> {
    pub version: i16,
    pub algorithm: &'a [u8],
}

pub trait AsAkaAlgorithm<'a> {
    type Target;
    type Err;
    fn as_aka_algorithm(&'a self) -> Result<Self::Target, Self::Err>;
}

impl<'a> AsAkaAlgorithm<'a> for [u8] {
    type Target = AkaAlgorithm<'a>;
    type Err = ();
    fn as_aka_algorithm(&'a self) -> Result<AkaAlgorithm<'a>, ()> {
        let mut iter = self.into_iter();

        if let Some(5) = iter.position(|c| *c == b'-') {
            if self.start_with(b"AKAv1") {
                return Ok(AkaAlgorithm {
                    version: 1,
                    algorithm: &self[6..],
                });
            }
        }

        Err(())
    }
}

pub struct AkaChallenge {
    pub rand: [u8; 16],
    pub autn: [u8; 16],
}

impl FromRawStr for AkaChallenge {
    type Err = ();
    fn from_raw_str(s: &[u8]) -> Result<AkaChallenge, ()> {
        if let Ok(s) = general_purpose::STANDARD.decode(s) {
            if s.len() >= 32 {
                let mut aka_challenge = AkaChallenge {
                    rand: [0; 16],
                    autn: [0; 16],
                };

                unsafe {
                    std::ptr::copy_nonoverlapping(
                        s[..16].as_ptr(),
                        aka_challenge.rand.as_mut_ptr(),
                        16,
                    );
                    std::ptr::copy_nonoverlapping(
                        s[16..32].as_ptr(),
                        aka_challenge.autn.as_mut_ptr(),
                        16,
                    );
                }

                return Ok(aka_challenge);
            }
        }

        Err(())
    }
}

pub enum AkaResponse {
    Successful(Vec<u8>, Option<(Vec<u8>, Vec<u8>)>),
    SyncFailure(Vec<u8>),
}

fn aka_decode_response(data: Vec<u8>) -> Result<AkaResponse, ErrorKind> {
    if data.len() >= 2 {
        let tag = data[0];
        if tag == 0xDB {
            let res_length = data[1] as usize;
            platform_log(LOG_TAG, format!("res_length:{}", res_length));
            if data.len() >= 2 + res_length {
                let mut res = Vec::with_capacity(res_length);
                res.extend_from_slice(&data[2..2 + res_length]);
                platform_log(LOG_TAG, format!("res:{}", &HEXUPPER.encode(&res)));
                if data.len() > 2 + res_length {
                    let ck_length = data[2 + res_length] as usize;
                    platform_log(LOG_TAG, format!("ck_length:{}", res_length));
                    if data.len() >= 2 + res_length + 1 + ck_length {
                        let mut ck = Vec::with_capacity(ck_length);
                        ck.extend_from_slice(
                            &data[2 + res_length + 1..2 + res_length + 1 + ck_length],
                        );
                        platform_log(LOG_TAG, format!("ck:{}", &HEXUPPER.encode(&ck)));
                        if data.len() > 2 + res_length + 1 + ck_length {
                            let ik_length = data[2 + res_length + 1 + ck_length] as usize;
                            platform_log(LOG_TAG, format!("ik_length:{}", ik_length));
                            if data.len() >= 2 + res_length + 1 + ck_length + 1 + ik_length {
                                let mut ik = Vec::with_capacity(ik_length);
                                ik.extend_from_slice(
                                    &data[2 + res_length + 1 + ck_length + 1
                                        ..2 + res_length + 1 + ck_length + 1 + ik_length],
                                );
                                platform_log(LOG_TAG, format!("ik:{}", &HEXUPPER.encode(&ik)));
                                return Ok(AkaResponse::Successful(res, Some((ck, ik))));
                            }
                        }
                    }
                }

                return Ok(AkaResponse::Successful(res, None));
            }
        } else if tag == 0xDC {
            let auts_length = data[1] as usize;
            platform_log(LOG_TAG, format!("auts_length:{}", auts_length));
            if data.len() >= 2 + auts_length {
                let mut auts = Vec::with_capacity(auts_length);
                auts.extend_from_slice(&data[2..2 + auts_length]);
                platform_log(LOG_TAG, format!("auts:{}", &HEXUPPER.encode(&auts)));
                return Ok(AkaResponse::SyncFailure(auts));
            }
        }
    }

    Err(ErrorKind::BadFormat)
}

pub fn aka_do_challenge(
    challenge: &AkaChallenge,
    subscription_id: i32,
) -> Result<AkaResponse, ErrorKind> {
    let mut challenge_data: [u8; 34] = [0; 34];

    challenge_data[0] = 16;
    challenge_data[17] = 16;

    unsafe {
        std::ptr::copy_nonoverlapping(
            challenge.rand.as_ptr(),
            challenge_data[1..17].as_mut_ptr(),
            16,
        );
        std::ptr::copy_nonoverlapping(
            challenge.autn.as_ptr(),
            challenge_data[18..].as_mut_ptr(),
            16,
        );
    }

    if PLATFORM_SUPPORT_DIRECT_AKA {
        if let Ok(data) = perform_aka(&challenge_data, subscription_id) {
            return aka_decode_response(data);
        }
    } else {
        let aid_bytes: [u8; 7] = [0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02];

        if let Some(channel) = IccChannel::new(&aid_bytes) {
            let cla = 0x00;
            let ins = 0x88;
            let p1 = 0x00;
            let p2 = 0x81;
            let lc = 0x22;
            let _le = 0x00;

            // let mut command : [u8; 5 + 34 + 1]  = [0; 5 + 34 + 1];

            // command[0] = cla;
            // command[1] = ins;
            // command[2] = p1;
            // command[3] = p2;
            // command[4] = lc;

            // unsafe {
            //     std::ptr::copy_nonoverlapping(challenge_data.as_ptr(), command[5..].as_mut_ptr(), 34);
            // }

            // command[39] = le;

            if let Ok(data) = channel.icc_exchange_apdu(cla, ins, p1, p2, lc, &challenge_data) {
                return aka_decode_response(data);
            }
        }
    }

    Err(ErrorKind::FFI)
}

pub enum ErrorKind {
    BadFormat,
    FFI,
    UnknownParameter,
}
