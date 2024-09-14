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
    io,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use libc::{AF_INET, AF_INET6, AF_UNIX};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ffi::{
    log::platform_log,
    ohos::sock::{
        close_socket, create_socket, get_socket_info, get_socket_local_address,
        get_socket_local_port, read_socket, shutdown_socket, socket_bind, socket_connect,
        socket_finish_connect, write_socket, SocketCHandleWrapper,
    },
    r#async::WakerHandle,
};

const LOG_TAG: &str = "socket";

pub struct OhosTcpStream {
    pub(crate) socket: SocketCHandleWrapper,
}

impl OhosTcpStream {
    pub fn create() -> io::Result<OhosTcpStream> {
        let socket = create_socket()?;
        Ok(OhosTcpStream { socket })
    }

    pub fn bind(&self, af: i32, ip: &str, port: u16) -> io::Result<()> {
        platform_log(LOG_TAG, "bind()");
        socket_bind(&self.socket, af, ip, port)
    }

    pub fn connect(self, ip: IpAddr, port: u16) -> io::Result<ConnectTask> {
        platform_log(LOG_TAG, "connect()");
        let remote_ip = ip.to_string();
        let af = if ip.is_ipv4() {
            AF_INET
        } else if ip.is_ipv6() {
            AF_INET6
        } else {
            AF_UNIX
        };
        socket_connect(&self.socket, af, &remote_ip, port)?;
        Ok(ConnectTask { stream: Some(self) })
    }

    pub fn get_local_addr(&self) -> Result<(String, u16), ()> {
        if let Some(sock_info) = get_socket_info(&self.socket) {
            if let Some(l_addr) = get_socket_local_address(&sock_info) {
                let l_port = get_socket_local_port(&sock_info);
                if l_port > 0 {
                    return Ok((format!("{}", l_addr), l_port)); // to-do: support ipv6
                }
            }
        }
        Err(())
    }

    pub fn get_local_address(&self) -> Result<String, ()> {
        if let Some(sock_info) = get_socket_info(&self.socket) {
            if let Some(l_addr) = get_socket_local_address(&sock_info) {
                let l_port = get_socket_local_port(&sock_info);
                if l_port > 0 {
                    return Ok(format!("{}:{}", l_addr, l_port)); // to-do: support ipv6
                }
            }
        }
        Err(())
    }
}

pub struct ConnectTask {
    pub stream: Option<OhosTcpStream>,
}

impl Future for ConnectTask {
    type Output = io::Result<OhosTcpStream>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "ConnectTask->poll()");
        let task = self.get_mut();
        match task.stream.take() {
            Some(stream) => {
                let waker = cx.waker();
                let waker = WakerHandle::new(waker);
                match socket_finish_connect(&stream.socket, waker) {
                    Ok(()) => {
                        platform_log(LOG_TAG, "ConnectTask->poll() result Ready");
                        Poll::Ready(Ok(stream))
                    }

                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            platform_log(LOG_TAG, "ConnectTask->poll() result Pending");
                            task.stream.replace(stream);
                            Poll::Pending
                        }

                        _ => {
                            platform_log(LOG_TAG, "ConnectTask->poll() result Error");
                            Poll::Ready(Err(e))
                        }
                    },
                }
            }

            None => {
                platform_log(LOG_TAG, "ConnectTask->poll() result Error");
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
    }
}

impl AsyncRead for OhosTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream = self.get_mut();

        let buffer = buf.initialize_unfilled();

        let waker = cx.waker();
        let waker = WakerHandle::new(waker);

        match read_socket(&stream.socket, buffer, waker) {
            Ok(r) => {
                buf.advance(r);
                return Poll::Ready(Ok(()));
            }

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }

                _ => {
                    return Poll::Ready(Err(e));
                }
            },
        }
    }
}

impl AsyncWrite for OhosTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let stream = self.get_mut();

        let waker = cx.waker();
        let waker = WakerHandle::new(waker);

        match write_socket(&stream.socket, buf, waker) {
            Ok(r) => {
                return Poll::Ready(Ok(r));
            }

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }

                _ => {
                    return Poll::Ready(Err(e));
                }
            },
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // tcp flush is a no-op
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();

        let waker = cx.waker();
        let waker = WakerHandle::new(waker);

        match shutdown_socket(&stream.socket, waker) {
            Ok(()) => {
                close_socket(&stream.socket);
                Poll::Ready(Ok(()))
            }
            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    return Poll::Pending;
                }

                _ => {
                    return Poll::Ready(Err(e));
                }
            },
        }
    }
}

unsafe impl Send for OhosTcpStream {}
