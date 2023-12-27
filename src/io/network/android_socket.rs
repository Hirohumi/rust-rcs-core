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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ffi::{
    android::sock::{
        cipher_suite_get_yy, cipher_suite_get_zz, close_socket, create_socket, get_socket_info,
        get_socket_local_address, get_socket_local_port, get_socket_session_cipher_suite,
        read_socket, shutdown_socket, socket_bind, socket_configure_tls, socket_connect,
        socket_finish_connect, socket_finish_handshake, socket_start_handshake, write_socket,
        SocketCHandleWrapper,
    },
    log::platform_log,
    r#async::WakerHandle,
};

const LOG_TAG: &str = "socket";

pub struct AndroidTcpStream {
    pub(crate) socket: SocketCHandleWrapper,
}

impl AndroidTcpStream {
    pub fn create() -> io::Result<AndroidTcpStream> {
        let socket = create_socket()?;
        Ok(AndroidTcpStream { socket })
    }

    pub fn bind(&self, ip: &str, port: u16) -> io::Result<()> {
        socket_bind(&self.socket, ip, port)
    }

    pub fn configure_tls(self, host_name: &str) -> io::Result<AndroidTcpStream> {
        platform_log(LOG_TAG, "configure_tls()");
        socket_configure_tls(&self.socket, host_name)?;
        Ok(self)
    }

    pub fn connect(self, ip: IpAddr, port: u16) -> io::Result<ConnectTask> {
        platform_log(LOG_TAG, "connect()");
        let remote_ip = ip.to_string();
        socket_connect(&self.socket, &remote_ip, port)?;
        Ok(ConnectTask { stream: Some(self) })
    }

    pub fn start_handshake(&self) -> io::Result<()> {
        platform_log(LOG_TAG, "start_handshake()");
        socket_start_handshake(&self.socket)
    }

    pub fn poll_handshake(&self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let waker = cx.waker();
        let waker = WakerHandle::new(waker);
        match socket_finish_handshake(&self.socket, waker) {
            Ok(()) => Poll::Ready(Ok(())),

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,

                _ => Poll::Ready(Err(e)),
            },
        }
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

    pub fn get_cipher_suite(&self) -> Option<(u8, u8)> {
        if let Some(cipher_suite) = get_socket_session_cipher_suite(&self.socket) {
            let yy = cipher_suite_get_yy(&cipher_suite);
            let zz = cipher_suite_get_zz(&cipher_suite);
            return Some((yy, zz));
        }

        return None;
    }
}

pub struct ConnectTask {
    pub stream: Option<AndroidTcpStream>,
}

impl Future for ConnectTask {
    type Output = io::Result<AndroidTcpStream>;

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

impl AsyncRead for AndroidTcpStream {
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

impl AsyncWrite for AndroidTcpStream {
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

unsafe impl Send for AndroidTcpStream {}
