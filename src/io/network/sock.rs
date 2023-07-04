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

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    os::unix::prelude::FromRawFd,
};

use libc::{
    c_void, in6_addr, in_addr, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage,
    socklen_t, AF_INET, AF_INET6, EAGAIN, EALREADY, EINPROGRESS, O_NONBLOCK, SOL_SOCKET,
};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
use crate::ffi::sock::{get_in6addr_any, get_inaddr_any, ntop};

/**
 * needed since Socket2 crate does not cope well with async api
 */
pub struct NativeSocket {
    sock_fd: i32,
}

impl NativeSocket {
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn create(domain: i32, ty: i32, protocol: i32) -> Result<NativeSocket, ()> {
        let sock = unsafe { libc::socket(domain, ty, protocol) };
        if sock > 0 {
            let flag = true;
            let flag_len = std::mem::size_of_val(&flag);
            let flag = ((&flag) as *const bool).cast::<c_void>();
            let r = unsafe {
                libc::setsockopt(sock, SOL_SOCKET, O_NONBLOCK, flag, flag_len as socklen_t)
            };
            if r == 0 {
                return Ok(NativeSocket { sock_fd: sock });
            }
        }

        Err(())
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn create(domain: i32, ty: i32, protocol: i32) -> Result<NativeSocket, ()> {
        Err(())
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn bind_interface(&self, af: i32) -> Result<(String, u16), std::io::Error> {
        let (mut storage, mut sock_len) = if af == AF_INET {
            get_inaddr_any()
        } else if af == AF_INET6 {
            get_in6addr_any()
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "not handled",
            ));
        };

        let sockaddr = (&storage as *const sockaddr_storage).cast::<sockaddr>();
        let r = unsafe { libc::bind(self.sock_fd, sockaddr, sock_len) };

        if r < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "not handled",
            ));
        }

        let sockaddr = (&mut storage as *mut sockaddr_storage).cast::<sockaddr>();
        let r = unsafe { libc::getsockname(self.sock_fd, sockaddr, &mut sock_len) };

        if r < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "not handled",
            ));
        }

        let sockaddr = (&storage as *const sockaddr_storage).cast::<sockaddr>();
        let port = unsafe {
            if (*sockaddr).sa_family == AF_INET as sa_family_t {
                (*sockaddr.cast::<sockaddr_in>()).sin_port
            } else if (*sockaddr).sa_family == AF_INET6 as sa_family_t {
                (*sockaddr.cast::<sockaddr_in6>()).sin6_port
            } else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "not handled",
                ));
            }
        };

        if let Some(network_address) = ntop(af, storage) {
            return Ok((network_address, port));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "not handled",
        ))
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn bind_interface(&self, af: i32) -> Result<(String, u16), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "error"))
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub fn connect(&self, addr: &String, port: u16) -> Result<(), std::io::Error> {
        match addr.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(addr)) => {
                // SAFETY: `Ipv4Addr` is `#[repr(C)] struct { _: in_addr; }`.
                // It is safe to cast from `&Ipv4Addr` to `&in_addr`.
                let addr = addr.ip() as *const Ipv4Addr as *const in_addr;
                let addr = sockaddr_in {
                    sin_family: AF_INET as sa_family_t,
                    sin_port: port.to_be(),
                    sin_addr: unsafe { *addr },
                    ..unsafe { std::mem::zeroed() }
                };

                let len = std::mem::size_of::<sockaddr_in>() as socklen_t;
                let address = (&addr as *const sockaddr_in).cast::<sockaddr>();
                let r = unsafe { libc::connect(self.sock_fd, address, len) };
                if r == 0 || r == EAGAIN || r == EALREADY || r == EINPROGRESS {
                    return Ok(());
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "not handled",
                ))
            }

            Ok(SocketAddr::V6(addr)) => {
                let flowinfo = addr.flowinfo();
                let scope_id = addr.scope_id();
                let addr = addr.ip() as *const Ipv6Addr as *const in6_addr;
                let addr = sockaddr_in6 {
                    sin6_family: AF_INET6 as sa_family_t,
                    sin6_port: port.to_be(),
                    sin6_addr: unsafe { *addr },
                    sin6_flowinfo: flowinfo,
                    sin6_scope_id: scope_id,
                    ..unsafe { std::mem::zeroed() }
                };

                let len = std::mem::size_of::<sockaddr_in6>() as socklen_t;
                let address = (&addr as *const sockaddr_in6).cast::<sockaddr>();
                let r = unsafe { libc::connect(self.sock_fd, address, len) };
                if r == 0 || r == EAGAIN || r == EALREADY || r == EINPROGRESS {
                    return Ok(());
                }

                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "not handled",
                ))
            }

            Err(e) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "not handled",
            )),
        }
    }

    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    pub fn connect(&self, addr: &String, port: u16) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "error"))
    }
}

impl From<NativeSocket> for TcpStream {
    fn from(mut sock: NativeSocket) -> Self {
        let stream = unsafe { TcpStream::from_raw_fd(sock.sock_fd) };
        sock.sock_fd = 0; // to-do: well well well
        stream
    }
}

impl Drop for NativeSocket {
    fn drop(&mut self) {
        if self.sock_fd > 0 {
            unsafe { libc::close(self.sock_fd) };
        }
    }
}
