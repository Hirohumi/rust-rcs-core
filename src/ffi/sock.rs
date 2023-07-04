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

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use std::ffi::{CStr, CString};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use libc::{c_char, sockaddr_storage, socklen_t};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
extern "C" {
    fn platform_get_inaddr_any(c_struct: *mut sockaddr_storage) -> socklen_t;
    fn platform_get_in6addr_any(c_struct: *mut sockaddr_storage) -> socklen_t;
    fn platform_ntop(af: i32, c_struct: sockaddr_storage) -> *const c_char;
    fn platform_pton(
        af: i32,
        network_address: *const c_char,
        c_struct: *mut sockaddr_storage,
    ) -> i32;
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn get_inaddr_any() -> (sockaddr_storage, socklen_t) {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };

    let sock_len = unsafe { platform_get_inaddr_any(&mut storage) };

    (storage, sock_len)
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn get_in6addr_any() -> (sockaddr_storage, socklen_t) {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };

    let sock_len = unsafe { platform_get_in6addr_any(&mut storage) };

    (storage, sock_len)
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn ntop(af: i32, c_struct: sockaddr_storage) -> Option<String> {
    unsafe {
        if let Some(ptr) = platform_ntop(af, c_struct).as_ref() {
            let str = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            return Some(str);
        }
    }

    None
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub fn pton(af: i32, network_address: &str) -> Option<sockaddr_storage> {
    let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };

    if let Ok(network_address) = CString::new(network_address) {
        let r = unsafe { platform_pton(af, network_address.as_ptr(), &mut storage) };

        if r == 0 {
            return Some(storage);
        }
    }

    None
}
