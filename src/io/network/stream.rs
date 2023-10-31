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

extern crate rustls;
extern crate tokio;

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{
    fmt, io,
    io::{Read, Write},
};

use rustls::{ClientConfig, ClientConnection, ServerName, Stream};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::ffi::log::platform_log;

use super::android_socket::AndroidTcpStream;

pub enum AndroidStream {
    Tcp(AndroidTcpStream),
    Tls(AndroidTcpStream, TlsState),
}

pub enum TokioStream {
    Tcp(TcpStream),
    Tls(ClientConnection, TcpStream, TlsState),
}

pub enum ClientStream {
    AndroidNative(AndroidStream),
    Tokio(TokioStream),
}

impl ClientStream {
    pub async fn new_tokio_connected(stream: TcpStream) -> Result<ClientStream> {
        Ok(ClientStream::Tokio(TokioStream::Tcp(stream)))
    }

    pub async fn new_tokio_ssl_connected(
        config: Arc<ClientConfig>,
        stream: TcpStream,
        server_name: &str,
    ) -> Result<ClientStream> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name) {
                Ok(client) => Ok(ClientStream::Tokio(TokioStream::Tls(
                    client,
                    stream,
                    TlsState::Connected,
                ))),
                Err(_) => Err(ErrorKind::Rustls),
            },
            Err(_) => Err(ErrorKind::Webpki),
        }
    }

    pub async fn new_android(dst_ip: IpAddr, dst_port: u16) -> Result<ClientStream> {
        match AndroidTcpStream::create(false, "") {
            Ok(stream) => match stream.connect(dst_ip, dst_port) {
                Ok(task) => match task.await {
                    Ok(stream) => Ok(ClientStream::AndroidNative(AndroidStream::Tcp(stream))),
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    pub async fn new_tokio(dst_ip: IpAddr, dst_port: u16) -> Result<ClientStream> {
        match TcpStream::connect((dst_ip, dst_port)).await {
            Ok(stream) => Ok(ClientStream::Tokio(TokioStream::Tcp(stream))),
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    pub async fn new_android_ssl(ip: IpAddr, port: u16, host_name: &str) -> Result<ClientStream> {
        match AndroidTcpStream::create(true, host_name) {
            Ok(stream) => match stream.connect(ip, port) {
                Ok(task) => match task.await {
                    Ok(stream) => Ok(ClientStream::AndroidNative(AndroidStream::Tls(
                        stream,
                        TlsState::Connected,
                    ))),
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    pub async fn new_tokio_ssl(
        config: Arc<ClientConfig>,
        ip: IpAddr,
        port: u16,
        server_name: &str,
    ) -> Result<ClientStream> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name) {
                Ok(client) => match TcpStream::connect((ip, port)).await {
                    Ok(stream) => Ok(ClientStream::Tokio(TokioStream::Tls(
                        client,
                        stream,
                        TlsState::Connected,
                    ))),
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Rustls),
            },
            Err(_) => Err(ErrorKind::Webpki),
        }
    }

    pub fn get_local_transport_address(&self) -> String {
        match self {
            ClientStream::AndroidNative(stream) => match stream {
                AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                    if let Ok(addr) = stream.get_local_address() {
                        return addr;
                    }
                }
            },

            ClientStream::Tokio(stream) => match stream {
                TokioStream::Tcp(stream) | TokioStream::Tls(_, stream, _) => {
                    if let Ok(l_addr) = stream.local_addr() {
                        let l_port = l_addr.port();
                        match l_addr.ip() {
                            IpAddr::V4(ip) => return format!("{}:{}", ip, l_port),
                            IpAddr::V6(ip) => return format!("[{}]:{}", ip, l_port),
                        }
                    }
                }
            },
        }

        String::from("0.0.0.0:0")
    }

    pub fn do_handshake(self) -> Handshaker {
        match self {
            ClientStream::AndroidNative(stream) => Handshaker::AndroidNative(AndroidHandshaker {
                stream: Some(stream),
            }),

            ClientStream::Tokio(stream) => Handshaker::Tokio(TokioHandshaker {
                stream: Some(stream),
            }),
        }
    }
}

pub enum TlsState {
    Connected,
    Negotiated(u8, u8),
    Shutdown,
}

pub enum Handshaker {
    AndroidNative(AndroidHandshaker),
    Tokio(TokioHandshaker),
}

impl Future for Handshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Handshaker::AndroidNative(task) => Pin::new(task).poll(cx),
            Handshaker::Tokio(task) => Pin::new(task).poll(cx),
        }
    }
}

pub struct AndroidHandshaker {
    stream: Option<AndroidStream>,
}

impl Future for AndroidHandshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task = self.get_mut();
        match task.stream.take() {
            Some(mut stream) => match stream {
                AndroidStream::Tcp(_) => {
                    Poll::Ready(Ok((ClientStream::AndroidNative(stream), None)))
                }
                AndroidStream::Tls(ref mut tcp_stream, ref mut state) => match *state {
                    TlsState::Connected => match tcp_stream.poll_handshake(cx) {
                        Poll::Ready(r) => match r {
                            Ok(()) => {
                                if let Some((cipher_id_h, cipher_id_l)) =
                                    tcp_stream.get_cipher_suite()
                                {
                                    *state = TlsState::Negotiated(cipher_id_h, cipher_id_l);
                                    Poll::Ready(Ok((
                                        ClientStream::AndroidNative(stream),
                                        Some((cipher_id_h, cipher_id_l)),
                                    )))
                                } else {
                                    Poll::Ready(Err(ErrorKind::HandshakeFailure))
                                }
                            }
                            Err(e) => Poll::Ready(Err(ErrorKind::HandshakeFailure)),
                        },
                        Poll::Pending => {
                            task.stream.replace(stream);
                            Poll::Pending
                        }
                    },
                    TlsState::Negotiated(cipher_id_h, cipher_id_l) => {
                        return Poll::Ready(Ok((
                            ClientStream::AndroidNative(stream),
                            Some((cipher_id_h, cipher_id_l)),
                        )));
                    }
                    TlsState::Shutdown => Poll::Ready(Err(ErrorKind::Io)),
                },
            },

            None => Poll::Ready(Err(ErrorKind::HandshakeFailure)),
        }
    }
}

pub struct TokioHandshaker {
    stream: Option<TokioStream>,
}

impl Future for TokioHandshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let task = self.get_mut();
        match task.stream.take() {
            Some(mut stream) => match stream {
                TokioStream::Tcp(_) => Poll::Ready(Ok((ClientStream::Tokio(stream), None))),
                TokioStream::Tls(ref mut conn, ref mut tcp_stream, ref mut state) => match *state {
                    TlsState::Connected => {
                        let mut sync_stream = SyncTcpStream {
                            stream: tcp_stream,
                            cx,
                        };
                        if conn.is_handshaking() {
                            platform_log(
                                "ssl",
                                "completing io before retrieving negotiated cipher suite",
                            );
                            match conn.complete_io(&mut sync_stream) {
                                Ok(_) => {
                                    if let Some(suite) = conn.negotiated_cipher_suite() {
                                        let cipher_id = suite.suite().get_u16().to_be_bytes();
                                        let (cipher_id_h, cipher_id_l) =
                                            (cipher_id[0], cipher_id[1]);
                                        *state = TlsState::Negotiated(cipher_id_h, cipher_id_l);
                                        Poll::Ready(Ok((
                                            ClientStream::Tokio(stream),
                                            Some((cipher_id_h, cipher_id_l)),
                                        )))
                                    } else {
                                        Poll::Ready(Err(ErrorKind::HandshakeFailure))
                                    }
                                }

                                Err(e) => match e.kind() {
                                    io::ErrorKind::WouldBlock => {
                                        platform_log("ssl", "WouldBlock");
                                        task.stream.replace(stream);
                                        Poll::Pending
                                    }
                                    io::ErrorKind::InvalidData => {
                                        platform_log("ssl", "InvalidData");
                                        Poll::Ready(Err(ErrorKind::Io))
                                    }
                                    _ => Poll::Ready(Err(ErrorKind::Io)),
                                },
                            }
                        } else {
                            if let Some(suite) = conn.negotiated_cipher_suite() {
                                let cipher_id = suite.suite().get_u16().to_be_bytes();
                                let (cipher_id_h, cipher_id_l) = (cipher_id[0], cipher_id[1]);
                                *state = TlsState::Negotiated(cipher_id_h, cipher_id_l);
                                Poll::Ready(Ok((
                                    ClientStream::Tokio(stream),
                                    Some((cipher_id_h, cipher_id_l)),
                                )))
                            } else {
                                Poll::Ready(Err(ErrorKind::HandshakeFailure))
                            }
                        }
                    }

                    TlsState::Negotiated(cipher_id_h, cipher_id_l) => {
                        return Poll::Ready(Ok((
                            ClientStream::Tokio(stream),
                            Some((cipher_id_h, cipher_id_l)),
                        )));
                    }

                    TlsState::Shutdown => Poll::Ready(Err(ErrorKind::Io)),
                },
            },

            None => Poll::Ready(Err(ErrorKind::HandshakeFailure)),
        }
    }
}

struct SyncTcpStream<'a, 'b> {
    stream: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
}

impl Read for SyncTcpStream<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = ReadBuf::new(buf);
        match Pin::new(&mut self.stream).poll_read(self.cx, &mut buf) {
            Poll::Ready(Ok(())) => Ok(buf.filled().len()),

            Poll::Ready(Err(e)) => Err(e),

            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl Write for SyncTcpStream<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut self.stream).poll_write(self.cx, buf) {
            Poll::Ready(Ok(size)) => Ok(size),

            Poll::Ready(Err(e)) => Err(e),

            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut self.stream).poll_flush(self.cx) {
            Poll::Ready(ok) => ok,

            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::AndroidNative(stream) => match stream {
                AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                    Pin::new(stream).poll_read(cx, buf)
                }
            },

            ClientStream::Tokio(stream) => match stream {
                TokioStream::Tcp(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
                TokioStream::Tls(ref mut conn, ref mut stream, state) => match *state {
                    TlsState::Connected | TlsState::Negotiated(_, _) => {
                        let mut stream = SyncTcpStream { stream, cx };
                        let mut tls_stream = Stream::new(conn, &mut stream);
                        match tls_stream.read(buf.initialize_unfilled()) {
                            Ok(size) => {
                                buf.advance(size);
                                Poll::Ready(Ok(()))
                            }

                            Err(e) => match e.kind() {
                                io::ErrorKind::WouldBlock => Poll::Pending,
                                _ => Poll::Ready(Err(e)),
                            },
                        }
                    }

                    TlsState::Shutdown => Poll::Ready(Ok(())),
                },
            },
        }
    }
}

impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            ClientStream::AndroidNative(stream) => match stream {
                AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                    Pin::new(stream).poll_write(cx, buf)
                }
            },

            ClientStream::Tokio(stream) => match stream {
                TokioStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
                TokioStream::Tls(ref mut conn, ref mut stream, _) => {
                    let mut stream = SyncTcpStream { stream, cx };
                    let mut tls_stream = Stream::new(conn, &mut stream);
                    match tls_stream.write(buf) {
                        Ok(size) => Poll::Ready(Ok(size)),

                        Err(e) => match e.kind() {
                            io::ErrorKind::WouldBlock => Poll::Pending,
                            _ => Poll::Ready(Err(e)),
                        },
                    }
                }
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::AndroidNative(stream) => match stream {
                AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                    Pin::new(stream).poll_flush(cx)
                }
            },

            ClientStream::Tokio(stream) => match stream {
                TokioStream::Tcp(ref mut stream) => Pin::new(stream).poll_flush(cx),
                TokioStream::Tls(ref mut conn, ref mut stream, _) => {
                    let mut stream = SyncTcpStream { stream, cx };
                    let mut tls_stream = Stream::new(conn, &mut stream);
                    match tls_stream.flush() {
                        Ok(()) => Poll::Ready(Ok(())),

                        Err(e) => match e.kind() {
                            io::ErrorKind::WouldBlock => Poll::Pending,
                            _ => Poll::Ready(Err(e)),
                        },
                    }
                }
            },
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            ClientStream::AndroidNative(stream) => match stream {
                AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                    Pin::new(stream).poll_shutdown(cx)
                }
            },

            ClientStream::Tokio(stream) => match stream {
                TokioStream::Tcp(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
                TokioStream::Tls(ref mut conn, ref mut stream, ref mut state) => {
                    match *state {
                        TlsState::Connected => {
                            *state = TlsState::Shutdown;
                        }

                        TlsState::Negotiated(_, _) => {
                            conn.send_close_notify();
                            *state = TlsState::Shutdown;
                        }

                        TlsState::Shutdown => {}
                    }

                    while conn.wants_write() {
                        let mut stream = SyncTcpStream { stream, cx };
                        match conn.write_tls(&mut stream) {
                            Ok(_) => {
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

                    Pin::new(stream).poll_shutdown(cx)
                }
            },
        }
    }
}

pub enum ErrorKind {
    HandshakeFailure,
    Io,
    Rustls,
    Webpki,
}

impl Copy for ErrorKind {}

impl Clone for ErrorKind {
    fn clone(&self) -> ErrorKind {
        *self
    }
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::HandshakeFailure => {
                write!(f, "HandshakeFailure")
            }

            ErrorKind::Io => {
                write!(f, "Io")
            }

            ErrorKind::Rustls => {
                write!(f, "Rustls")
            }

            ErrorKind::Webpki => {
                write!(f, "Webpki")
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, ErrorKind>;
