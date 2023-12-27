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

extern crate libc;

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
use libc::{c_int, c_void, size_t};

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" {
    fn platform_icc_open_channel(aid_bytes: *const u8, aid_size: size_t) -> c_int;
    fn platform_icc_exchange_apdu(
        channel: c_int,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        p3: u8,
        in_data: *const u8,
        in_size: size_t,
        out_size: *mut size_t,
    ) -> *const u8;
    fn platform_icc_close_channel(channel: c_int);
}

pub struct IccChannel {
    channel: i32,
}

impl IccChannel {
    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    pub fn new(aid_bytes: &[u8]) -> Option<IccChannel> {
        unsafe {
            let channel = platform_icc_open_channel(aid_bytes.as_ptr(), aid_bytes.len());
            if channel >= 0 {
                Some(IccChannel { channel })
            } else {
                None
            }
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub fn new(aid_bytes: &[u8]) -> Option<IccChannel> {
        None
    }

    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    pub fn icc_exchange_apdu(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        p3: u8,
        in_data: &[u8],
    ) -> Result<Vec<u8>, ErrorKind> {
        unsafe {
            let mut out_size: size_t = 0;
            let out_data = platform_icc_exchange_apdu(
                self.channel,
                cla,
                ins,
                p1,
                p2,
                p3,
                in_data.as_ptr(),
                in_data.len(),
                &mut out_size,
            );

            if out_size <= 0 || out_data == std::ptr::null() {
                return Err(ErrorKind::InvocationFailure);
            }

            let mut data = Vec::with_capacity(out_size);

            std::ptr::copy_nonoverlapping(out_data, data.as_mut_ptr(), out_size);

            libc::free(out_data as *mut c_void);

            data.set_len(out_size);

            Ok(data)
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub fn icc_exchange_apdu(
        &self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        p3: u8,
        in_data: &[u8],
    ) -> Result<Vec<u8>, ErrorKind> {
        Err(ErrorKind::InvocationFailure)
    }
}

impl Drop for IccChannel {
    fn drop(&mut self) {
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        unsafe {
            platform_icc_close_channel(self.channel)
        }
    }
}

pub enum ErrorKind {
    InvocationFailure,
}
