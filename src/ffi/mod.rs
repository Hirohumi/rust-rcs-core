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

use std::ffi::CString;

use libc::c_char;

#[cfg(all(feature = "android", target_os = "android"))]
pub mod android;
pub mod r#async;
pub mod icc;
pub mod log;
pub mod net_ctrl;
#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub mod ohos;

#[no_mangle]
pub unsafe extern "C" fn librust_free_cstring(cstr: *mut c_char) {
    _ = CString::from_raw(cstr);
}
