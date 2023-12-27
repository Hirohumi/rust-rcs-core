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

use std::ffi::CString;

use libc::c_char;

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" {
    fn platform_log_impl(tag: *const c_char, message: *const c_char);
}

#[cfg(debug_assertions)]
pub fn platform_log<M>(tag: &str, message: M)
where
    M: AsRef<str>,
{
    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    if let (Ok(tag), Ok(message)) = (CString::new(tag), CString::new(message.as_ref())) {
        let c_tag = (&tag).as_ptr();
        let c_message = (&message).as_ptr();
        unsafe {
            platform_log_impl(c_tag, c_message);
        }
    }
    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    println!("{}:   {}", tag, message.as_ref());
}

#[cfg(not(debug_assertions))]
pub fn platform_log<M>(tag: &str, message: M)
where
    M: AsRef<str>,
{
}
