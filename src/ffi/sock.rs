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
use std::{io, ptr::NonNull};

use libc::c_void;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use libc::{c_char, size_t, sockaddr_storage, socklen_t};

use crate::ffi::log::platform_log;

use super::r#async::WakerHandle;

const LOG_TAG: &str = "ffi";

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

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
extern "C" {
    fn platform_create_socket(use_tls: bool, host_name: *const c_char) -> *mut SocketCHandle;
    fn platform_socket_connect(
        c_handle: *mut SocketCHandle,
        remote_ip: *const c_char,
        remote_port: u16,
    ) -> i32;
    fn platform_socket_finish_connect(
        c_handle: *mut SocketCHandle,
        waker_handle: *mut c_void,
    ) -> i32; // returns 0 for success, 114 (EALREADY) for pending status
    fn platform_socket_start_handshake(c_handle: *mut SocketCHandle) -> i32;
    fn platform_socket_finish_handshake(
        c_handle: *mut SocketCHandle,
        waker_handle: *mut c_void,
    ) -> i32; // returns 0 for success, 114 (EALREADY) for pending status
    fn platform_read_socket(
        c_handle: *mut SocketCHandle,
        waker_handle: *mut c_void,
        buffer: *mut u8,
        buffer_len: size_t,
        bytes_read: *mut size_t,
    ) -> i32; // returns 0 for success, 11 (EAGAIN/EWOULDBLOCK) for pending status
    fn platform_write_socket(
        c_handle: *mut SocketCHandle,
        waker_handle: *mut c_void,
        buffer: *const u8,
        buffer_len: size_t,
        bytes_written: *mut size_t,
    ) -> i32; // returns 0 for success, 11 (EAGAIN/EWOULDBLOCK) for pending status
    fn platform_shutdown_socket(c_handle: *mut SocketCHandle, waker_handle: *mut c_void) -> i32; // returns 0 for success, 114 (EALREADY) for pending status
    fn platform_close_socket(c_handle: *mut SocketCHandle);
    fn platform_free_socket(c_handle: *mut SocketCHandle);
}

#[repr(C)]
pub struct SocketCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct SocketCHandleWrapper(NonNull<SocketCHandle>);

impl Drop for SocketCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        unsafe {
            platform_free_socket(c_handle);
        }
    }
}

unsafe impl Send for SocketCHandleWrapper {}

pub fn create_socket(tls: bool, host_name: &str) -> io::Result<SocketCHandleWrapper> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let host_name = CString::new(host_name).unwrap();
        let host_name = host_name.as_ptr();
        unsafe {
            if let Some(c_handle) = platform_create_socket(tls, host_name).as_mut() {
                return Ok(SocketCHandleWrapper(NonNull::new(c_handle).unwrap()));
            }
        }
    }

    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn socket_connect(
    c_socket: &SocketCHandleWrapper,
    remote_ip: &str,
    remote_port: u16,
) -> io::Result<()> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let remote_ip = CString::new(remote_ip).unwrap();
        let remote_ip = remote_ip.as_ptr();
        unsafe {
            let r = platform_socket_connect(c_socket, remote_ip, remote_port);
            platform_log(LOG_TAG, format!("platform_socket_connect returns {}", r));
            if r == 0 {
                return Ok(());
            } else if r == libc::EAGAIN || r == libc::EWOULDBLOCK {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn socket_finish_connect(
    c_socket: &SocketCHandleWrapper,
    waker: WakerHandle,
) -> io::Result<()> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let waker = Box::new(waker);
        let waker = Box::into_raw(waker);
        let waker = waker as *mut c_void;
        unsafe {
            let r = platform_socket_finish_connect(c_socket, waker);
            platform_log(
                LOG_TAG,
                format!("platform_socket_finish_connect returns {}", r),
            );
            if r == 0 {
                return Ok(());
            } else if r == libc::EALREADY {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn socket_start_handshake(c_socket: &SocketCHandleWrapper) -> io::Result<()> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        unsafe {
            let r = platform_socket_start_handshake(c_socket);
            platform_log(
                LOG_TAG,
                format!("platform_socket_start_handshake returns {}", r),
            );
            if r == 0 {
                return Ok(());
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn socket_finish_handshake(
    c_socket: &SocketCHandleWrapper,
    waker: WakerHandle,
) -> io::Result<()> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let waker = Box::new(waker);
        let waker = Box::into_raw(waker);
        let waker = waker as *mut c_void;
        unsafe {
            let r = platform_socket_finish_handshake(c_socket, waker);
            platform_log(
                LOG_TAG,
                format!("platform_socket_finish_handshake returns {}", r),
            );
            if r == 0 {
                return Ok(());
            } else if r == libc::EALREADY {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn read_socket(
    c_socket: &SocketCHandleWrapper,
    buffer: &mut [u8],
    waker: WakerHandle,
) -> io::Result<usize> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let buffer_len = buffer.len();
        let buffer = buffer.as_mut_ptr();
        let waker = Box::new(waker);
        let waker = Box::into_raw(waker);
        let waker = waker as *mut c_void;
        unsafe {
            let mut bytes_read = 0;
            let r = platform_read_socket(c_socket, waker, buffer, buffer_len, &mut bytes_read);
            platform_log(
                LOG_TAG,
                format!(
                    "platform_read_socket returns {} with {} bytes read",
                    r, bytes_read
                ),
            );
            if r == 0 {
                return Ok(bytes_read);
            } else if r == libc::EAGAIN || r == libc::EWOULDBLOCK {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn write_socket(
    c_socket: &SocketCHandleWrapper,
    buffer: &[u8],
    waker: WakerHandle,
) -> io::Result<usize> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let buffer_len = buffer.len();
        let buffer = buffer.as_ptr();
        let waker = Box::new(waker);
        let waker = Box::into_raw(waker);
        let waker = waker as *mut c_void;
        unsafe {
            let mut bytes_written = 0;
            let r = platform_write_socket(c_socket, waker, buffer, buffer_len, &mut bytes_written);
            platform_log(
                LOG_TAG,
                format!(
                    "platform_write_socket returns {} with {} bytes written",
                    r, bytes_written
                ),
            );
            if r == 0 {
                return Ok(bytes_written);
            } else if r == libc::EAGAIN || r == libc::EWOULDBLOCK {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn shutdown_socket(c_socket: &SocketCHandleWrapper, waker: WakerHandle) -> io::Result<()> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        let waker = Box::new(waker);
        let waker = Box::into_raw(waker);
        let waker = waker as *mut c_void;
        unsafe {
            let r = platform_shutdown_socket(c_socket, waker);
            platform_log(LOG_TAG, format!("platform_shutdown_socket returns {}", r));
            if r == 0 {
                return Ok(());
            } else if r == libc::EALREADY {
                return Err(io::Error::from(io::ErrorKind::WouldBlock));
            } else {
                return Err(io::Error::from(io::ErrorKind::Other));
            }
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    Err(io::Error::from(io::ErrorKind::Unsupported))
}

pub fn close_socket(c_socket: &SocketCHandleWrapper) {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    {
        let c_socket = c_socket.0.as_ptr();
        unsafe {
            platform_close_socket(c_socket);
        }
    }
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
extern "C" {
    fn platform_get_socket_info(socket_c_handle: *mut SocketCHandle) -> *mut SocketInfoCHandle;
    fn platform_get_socket_af(c_handle: *mut SocketInfoCHandle) -> i32;
    fn platform_get_socket_l_addr(c_handle: *mut SocketInfoCHandle) -> *const c_char;
    fn platform_get_socket_l_port(c_handle: *mut SocketInfoCHandle) -> u16;
    fn platform_free_socket_info(c_handle: *mut SocketInfoCHandle);
}

#[repr(C)]
pub struct SocketInfoCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct SocketInfoCHandleWrapper(NonNull<SocketInfoCHandle>);

impl Drop for SocketInfoCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        unsafe {
            platform_free_socket_info(c_handle);
        }
    }
}

unsafe impl Send for SocketInfoCHandleWrapper {}

pub fn get_socket_info(android_socket: &SocketCHandleWrapper) -> Option<SocketInfoCHandleWrapper> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let android_socket = android_socket.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        if let Some(c_handle) = platform_get_socket_info(android_socket).as_mut() {
            return Some(SocketInfoCHandleWrapper(NonNull::new(c_handle).unwrap()));
        }
    }

    None
}

pub fn get_socket_af(android_socket_info: &SocketInfoCHandleWrapper) -> i32 {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let android_socket_info = android_socket_info.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        return platform_get_socket_af(android_socket_info);
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    0
}

pub fn get_socket_local_address(android_socket_info: &SocketInfoCHandleWrapper) -> Option<String> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let android_socket_info = android_socket_info.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        if let Some(ptr) = platform_get_socket_l_addr(android_socket_info).as_ref() {
            let str = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            return Some(str);
        }
    }

    None
}

pub fn get_socket_local_port(android_socket_info: &SocketInfoCHandleWrapper) -> u16 {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let android_socket_info = android_socket_info.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        return platform_get_socket_l_port(android_socket_info);
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    0
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
extern "C" {
    fn platform_get_socket_session_cipher_suite(
        socket_c_handle: *mut SocketCHandle,
    ) -> *mut CipherSuiteCHandle;
    fn platform_cipher_suite_get_yy(c_handle: *mut CipherSuiteCHandle) -> u8;
    fn platform_cipher_suite_get_zz(c_handle: *mut CipherSuiteCHandle) -> u8;
    fn platform_free_cipher_suite(c_handle: *mut CipherSuiteCHandle);
}

#[repr(C)]
pub struct CipherSuiteCHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

pub struct CipherSuiteCHandleWrapper(NonNull<CipherSuiteCHandle>);

impl Drop for CipherSuiteCHandleWrapper {
    fn drop(&mut self) {
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        let c_handle = self.0.as_ptr();
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        unsafe {
            platform_free_cipher_suite(c_handle);
        }
    }
}

unsafe impl Send for CipherSuiteCHandleWrapper {}

pub fn get_socket_session_cipher_suite(
    android_socket: &SocketCHandleWrapper,
) -> Option<CipherSuiteCHandleWrapper> {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let android_socket = android_socket.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        if let Some(c_handle) = platform_get_socket_session_cipher_suite(android_socket).as_mut() {
            return Some(CipherSuiteCHandleWrapper(NonNull::new(c_handle).unwrap()));
        }
    }

    None
}

pub fn cipher_suite_get_yy(c_cipher_suite: &CipherSuiteCHandleWrapper) -> u8 {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let c_cipher_suite = c_cipher_suite.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        return platform_cipher_suite_get_yy(c_cipher_suite);
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    0
}

pub fn cipher_suite_get_zz(c_cipher_suite: &CipherSuiteCHandleWrapper) -> u8 {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    let c_cipher_suite = c_cipher_suite.0.as_ptr();
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    unsafe {
        return platform_cipher_suite_get_zz(c_cipher_suite);
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    0
}
