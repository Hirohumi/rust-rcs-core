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

use std::{
    ffi::{c_void, CStr},
    net::SocketAddr,
    ptr::NonNull,
};

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
use libc::c_char;

pub struct NetworkRequestCallbackWrapper {
    callback: Option<Box<dyn FnOnce(bool) + Send + Sync + 'static>>,
}

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" fn network_activation_callback(ptr: *mut c_void, activated: bool) {
    let data = ptr as *mut NetworkRequestCallbackWrapper;

    unsafe {
        if let Some(wrapper) = data.as_mut() {
            if let Some(callback) = wrapper.callback.take() {
                callback(activated);
            }
        }
    }
}

#[repr(C)]
pub struct NetworkRequestCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct NetworkRequestCHandleWrapper(NonNull<NetworkRequestCHandle>);

impl Drop for NetworkRequestCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        unsafe {
            platform_drop_network_request(c_handle);
        }
    }
}

unsafe impl Send for NetworkRequestCHandleWrapper {}

#[repr(C)]
pub struct NetworkInfoCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct NetworkInfoCHandleWrapper(NonNull<NetworkInfoCHandle>);

impl Drop for NetworkInfoCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        unsafe {
            platform_drop_network_info(c_handle);
        }
    }
}

unsafe impl Send for NetworkInfoCHandleWrapper {}

#[repr(C)]
pub struct DnsInfoCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct DnsInfoCHandleWrapper(NonNull<DnsInfoCHandle>);

impl Drop for DnsInfoCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        ))]
        unsafe {
            platform_drop_dns_info(c_handle);
        }
    }
}

unsafe impl Send for DnsInfoCHandleWrapper {}

#[cfg(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
))]
extern "C" {
    fn platform_activate_cellular_network(
        ptr: *mut c_void,
        callback: Option<extern "C" fn(*mut c_void, bool)>,
    ) -> *mut NetworkRequestCHandle;
    fn platform_drop_network_request(c_handle: *mut NetworkRequestCHandle);
    fn platform_get_active_network_info() -> *mut NetworkInfoCHandle;
    fn platform_get_network_type(network_info: *mut NetworkInfoCHandle) -> i32;
    fn platform_get_network_dns_info(network_info: *mut NetworkInfoCHandle) -> *mut DnsInfoCHandle;
    fn platform_get_dns_server(dns_info: *mut DnsInfoCHandle) -> *const c_char;
    fn platform_drop_dns_info(dns_info: *mut DnsInfoCHandle);
    fn platform_drop_network_info(network_info: *mut NetworkInfoCHandle);
}

pub fn activate_cellular_network<T>(callback: T) -> Option<NetworkRequestCHandleWrapper>
where
    T: 'static + FnOnce(bool) + Send + Sync,
{
    let wrapper = NetworkRequestCallbackWrapper {
        callback: Some(Box::new(callback)),
    };

    let data = Box::into_raw(Box::new(wrapper));
    let ptr = data as *mut c_void;

    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        if let Some(c_handle) =
            platform_activate_cellular_network(ptr, Some(network_activation_callback)).as_mut()
        {
            return Some(NetworkRequestCHandleWrapper(
                NonNull::new(c_handle).unwrap(),
            ));
        }
    }

    None
}

pub fn get_active_network_info() -> Option<NetworkInfoCHandleWrapper> {
    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        if let Some(network_info) = platform_get_active_network_info().as_mut() {
            return Some(NetworkInfoCHandleWrapper(
                NonNull::new(network_info).unwrap(),
            ));
        }
    }

    None
}

pub fn get_network_type(network_info: &NetworkInfoCHandleWrapper) -> i32 {
    let network_info_c_handle = network_info.0.as_ptr();
    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        return platform_get_network_type(network_info_c_handle);
    }

    0
}

pub fn get_dns_info(network_info: &NetworkInfoCHandleWrapper) -> Option<DnsInfoCHandleWrapper> {
    let network_info_c_handle = network_info.0.as_ptr();

    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        if let Some(dns_info) = platform_get_network_dns_info(network_info_c_handle).as_mut() {
            return Some(DnsInfoCHandleWrapper(NonNull::new(dns_info).unwrap()));
        }
    }

    None
}

pub fn get_dns_servers(dns_info: &DnsInfoCHandleWrapper) -> Vec<SocketAddr> {
    let dns_info_c_handle = dns_info.0.as_ptr();

    let mut v = Vec::new();

    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        while let Some(ptr) = platform_get_dns_server(dns_info_c_handle).as_ref() {
            let str = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            if let Ok(dns_server) = str.parse::<SocketAddr>() {
                v.push(dns_server);
            }
        }
    }

    v
}

pub fn get_active_dns_servers() -> Vec<SocketAddr> {
    let mut v = Vec::new();

    #[cfg(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    ))]
    unsafe {
        if let Some(network_info) = platform_get_active_network_info().as_mut() {
            if let Some(dns_info) = platform_get_network_dns_info(network_info).as_mut() {
                while let Some(ptr) = platform_get_dns_server(dns_info).as_ref() {
                    let str = CStr::from_ptr(ptr).to_string_lossy().into_owned();
                    if let Ok(dns_server) = str.parse::<SocketAddr>() {
                        v.push(dns_server);
                    }
                }
                platform_drop_dns_info(dns_info);
            }
        }
    }

    v
}
