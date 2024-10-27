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
#[cfg(not(all(feature = "android", target_os = "android")))]
use std::io::{Read, Write};
use std::net::IpAddr;
use std::pin::Pin;
#[cfg(not(all(feature = "android", target_os = "android")))]
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{fmt, io};

#[cfg(not(all(feature = "android", target_os = "android")))]
use rustls::pki_types::ServerName;
#[cfg(not(all(feature = "android", target_os = "android")))]
use rustls::{ClientConfig, ClientConnection, Stream};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
use tokio::net::{TcpSocket, TcpStream};

use crate::ffi::log::platform_log;
use crate::sip::sip_transport::SipTransportType;

#[cfg(all(feature = "android", target_os = "android"))]
use super::android_socket::AndroidTcpStream;
#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
use super::ohos_socket::OhosTcpStream;

const LOG_TAG: &str = "socket_stream";

#[cfg(all(feature = "android", target_os = "android"))]
pub enum AndroidStream {
    Tcp(AndroidTcpStream),
    Tls(AndroidTcpStream, TlsState),
}

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub enum OhosStream {
    Tcp(OhosTcpStream),
    Tls(ClientConnection, OhosTcpStream, TlsState),
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
pub enum TokioStream {
    Tcp(TcpStream),
    Tls(ClientConnection, TcpStream, TlsState),
}

#[cfg(all(feature = "android", target_os = "android"))]
pub struct ClientSocket(pub AndroidTcpStream);

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub struct ClientSocket(pub OhosTcpStream);

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
pub struct ClientSocket(pub TcpSocket);

impl ClientSocket {
    #[cfg(all(feature = "android", target_os = "android"))]
    pub fn configure_tls(self, host_name: &str) -> Result<ClientSocket> {
        match self.0.configure_tls(host_name) {
            Ok(sock) => Ok(ClientSocket(sock)),
            Err(_) => Err(ErrorKind::Platform),
        }
    }

    #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
    pub fn configure_tls(
        &self,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<ClientConnection> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name.to_owned()) {
                Ok(cc) => Ok(cc),
                Err(_) => Err(ErrorKind::Rustls),
            },
            Err(_) => Err(ErrorKind::Webpki),
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub fn configure_tls(
        &self,
        config: Arc<ClientConfig>,
        server_name: &str,
    ) -> Result<ClientConnection> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name.to_owned()) {
                Ok(cc) => Ok(cc),
                Err(_) => Err(ErrorKind::Rustls),
            },
            Err(_) => Err(ErrorKind::Webpki),
        }
    }

    #[cfg(all(feature = "android", target_os = "android"))]
    pub async fn connect(self, ip: IpAddr, port: u16) -> Result<ClientStream> {
        match self.0.connect(ip, port) {
            Ok(task) => match task.await {
                Ok(stream) => Ok(ClientStream(AndroidStream::Tcp(stream))),
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
    pub async fn connect(
        self,
        ip: IpAddr,
        port: u16,
        cc: Option<ClientConnection>,
    ) -> Result<ClientStream> {
        match self.0.connect(ip, port) {
            Ok(task) => match task.await {
                Ok(stream) => {
                    if let Some(cc) = cc {
                        Ok(ClientStream(OhosStream::Tls(
                            cc,
                            stream,
                            TlsState::Connected,
                        )))
                    } else {
                        Ok(ClientStream(OhosStream::Tcp(stream)))
                    }
                }
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub async fn connect(
        self,
        ip: IpAddr,
        port: u16,
        cc: Option<ClientConnection>,
    ) -> Result<ClientStream> {
        match self.0.connect((ip, port).into()).await {
            Ok(stream) => {
                if let Some(cc) = cc {
                    Ok(ClientStream(TokioStream::Tls(
                        cc,
                        stream,
                        TlsState::Connected,
                    )))
                } else {
                    Ok(ClientStream(TokioStream::Tcp(stream)))
                }
            }
            Err(_) => Err(ErrorKind::Io),
        }
    }
}

#[cfg(all(feature = "android", target_os = "android"))]
pub struct ClientStream(AndroidStream);

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub struct ClientStream(OhosStream);

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
pub struct ClientStream(TokioStream);

impl ClientStream {
    #[cfg(all(feature = "android", target_os = "android"))]
    pub async fn new_android(dst_ip: IpAddr, dst_port: u16) -> Result<ClientStream> {
        match AndroidTcpStream::create() {
            Ok(stream) => match stream.connect(dst_ip, dst_port) {
                Ok(task) => match task.await {
                    Ok(stream) => Ok(ClientStream(AndroidStream::Tcp(stream))),
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
    pub async fn new_ohos(dst_ip: IpAddr, dst_port: u16) -> Result<ClientStream> {
        match OhosTcpStream::create() {
            Ok(stream) => match stream.connect(dst_ip, dst_port) {
                Ok(task) => match task.await {
                    Ok(stream) => Ok(ClientStream(OhosStream::Tcp(stream))),
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub async fn new_tokio(dst_ip: IpAddr, dst_port: u16) -> Result<ClientStream> {
        match TcpStream::connect((dst_ip, dst_port)).await {
            Ok(stream) => Ok(ClientStream(TokioStream::Tcp(stream))),
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(all(feature = "android", target_os = "android"))]
    pub async fn new_android_ssl(ip: IpAddr, port: u16, host_name: &str) -> Result<ClientStream> {
        match AndroidTcpStream::create() {
            Ok(stream) => match stream.configure_tls(host_name) {
                Ok(stream) => match stream.connect(ip, port) {
                    Ok(task) => match task.await {
                        Ok(stream) => match stream.start_handshake() {
                            Ok(()) => Ok(ClientStream(AndroidStream::Tls(
                                stream,
                                TlsState::Connected,
                            ))),
                            Err(_) => Err(ErrorKind::Io),
                        },
                        Err(_) => Err(ErrorKind::Io),
                    },
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Io),
            },
            Err(_) => Err(ErrorKind::Io),
        }
    }

    #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
    pub async fn new_ohos_ssl(
        config: Arc<ClientConfig>,
        ip: IpAddr,
        port: u16,
        server_name: &str,
    ) -> Result<ClientStream> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name.to_owned()) {
                Ok(client) => match OhosTcpStream::create() {
                    Ok(stream) => match stream.connect(ip, port) {
                        Ok(task) => match task.await {
                            Ok(stream) => Ok(ClientStream(OhosStream::Tls(
                                client,
                                stream,
                                TlsState::Connected,
                            ))),
                            Err(_) => Err(ErrorKind::Io),
                        },
                        Err(_) => Err(ErrorKind::Io),
                    },
                    Err(_) => Err(ErrorKind::Io),
                },
                Err(_) => Err(ErrorKind::Rustls),
            },
            Err(_) => Err(ErrorKind::Webpki),
        }
    }

    #[cfg(not(any(
        all(feature = "android", target_os = "android"),
        all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
    )))]
    pub async fn new_tokio_ssl(
        config: Arc<ClientConfig>,
        ip: IpAddr,
        port: u16,
        server_name: &str,
    ) -> Result<ClientStream> {
        match ServerName::try_from(server_name) {
            Ok(name) => match ClientConnection::new(config, name.to_owned()) {
                Ok(client) => match TcpStream::connect((ip, port)).await {
                    Ok(stream) => Ok(ClientStream(TokioStream::Tls(
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

    pub fn get_sip_transport_type(&self) -> SipTransportType {
        #[cfg(all(feature = "android", target_os = "android"))]
        match self.0 {
            AndroidStream::Tcp(_) => SipTransportType::TCP,
            AndroidStream::Tls(_, _) => SipTransportType::TLS,
        }

        #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
        match self.0 {
            OhosStream::Tcp(_) => SipTransportType::TCP,
            OhosStream::Tls(_, _, _) => SipTransportType::TLS,
        }

        #[cfg(not(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        )))]
        match self.0 {
            TokioStream::Tcp(_) => SipTransportType::TCP,
            TokioStream::Tls(_, _, _) => SipTransportType::TLS,
        }
    }

    pub fn get_local_transport_address(&self) -> String {
        #[cfg(all(feature = "android", target_os = "android"))]
        match &self.0 {
            AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                if let Ok(addr) = stream.get_local_address() {
                    return addr;
                }
            }
        }

        #[cfg(not(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        )))]
        match &self.0 {
            TokioStream::Tcp(stream) | TokioStream::Tls(_, stream, _) => {
                if let Ok(l_addr) = stream.local_addr() {
                    let l_port = l_addr.port();
                    match l_addr.ip() {
                        IpAddr::V4(ip) => return format!("{}:{}", ip, l_port),
                        IpAddr::V6(ip) => return format!("[{}]:{}", ip, l_port),
                    }
                }
            }
        }

        String::from("0.0.0.0:0")
    }

    pub fn do_handshake(self) -> Handshaker {
        #[cfg(all(feature = "android", target_os = "android"))]
        return Handshaker {
            stream: Some(self.0),
        };

        #[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
        return Handshaker {
            stream: Some(self.0),
        };

        #[cfg(not(any(
            all(feature = "android", target_os = "android"),
            all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
        )))]
        return Handshaker {
            stream: Some(self.0),
        };
    }
}

pub enum TlsState {
    Connected,
    Negotiated(u8, u8),
    Shutdown,
}

#[cfg(all(feature = "android", target_os = "android"))]
pub struct Handshaker {
    stream: Option<AndroidStream>,
}

#[cfg(all(feature = "android", target_os = "android"))]
impl Future for Handshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "Handshaker->poll()");
        let task = self.get_mut();
        match task.stream.take() {
            Some(mut stream) => match stream {
                AndroidStream::Tcp(_) => Poll::Ready(Ok((ClientStream(stream), None))),
                AndroidStream::Tls(ref mut tcp_stream, ref mut state) => match *state {
                    TlsState::Connected => match tcp_stream.poll_handshake(cx) {
                        Poll::Ready(r) => match r {
                            Ok(()) => {
                                if let Some((cipher_id_h, cipher_id_l)) =
                                    tcp_stream.get_cipher_suite()
                                {
                                    *state = TlsState::Negotiated(cipher_id_h, cipher_id_l);
                                    Poll::Ready(Ok((
                                        ClientStream(stream),
                                        Some((cipher_id_h, cipher_id_l)),
                                    )))
                                } else {
                                    Poll::Ready(Err(ErrorKind::HandshakeFailure))
                                }
                            }
                            Err(_) => Poll::Ready(Err(ErrorKind::HandshakeFailure)),
                        },
                        Poll::Pending => {
                            task.stream.replace(stream);
                            Poll::Pending
                        }
                    },
                    TlsState::Negotiated(cipher_id_h, cipher_id_l) => {
                        return Poll::Ready(Ok((
                            ClientStream(stream),
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

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
pub struct Handshaker {
    stream: Option<OhosStream>,
}

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
impl Future for Handshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "Handshaker->poll()");
        let task = self.get_mut();
        match task.stream.take() {
            Some(mut stream) => match stream {
                OhosStream::Tcp(_) => Poll::Ready(Ok((ClientStream(stream), None))),
                OhosStream::Tls(ref mut conn, ref mut tcp_stream, ref mut state) => match *state {
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
                                            ClientStream(stream),
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
                                    ClientStream(stream),
                                    Some((cipher_id_h, cipher_id_l)),
                                )))
                            } else {
                                Poll::Ready(Err(ErrorKind::HandshakeFailure))
                            }
                        }
                    }

                    TlsState::Negotiated(cipher_id_h, cipher_id_l) => {
                        return Poll::Ready(Ok((
                            ClientStream(stream),
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

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
pub struct Handshaker {
    stream: Option<TokioStream>,
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
impl Future for Handshaker {
    type Output = Result<(ClientStream, Option<(u8, u8)>)>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        platform_log(LOG_TAG, "Handshaker->poll()");
        let task = self.get_mut();
        match task.stream.take() {
            Some(mut stream) => match stream {
                TokioStream::Tcp(_) => Poll::Ready(Ok((ClientStream(stream), None))),
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
                                            ClientStream(stream),
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
                                    ClientStream(stream),
                                    Some((cipher_id_h, cipher_id_l)),
                                )))
                            } else {
                                Poll::Ready(Err(ErrorKind::HandshakeFailure))
                            }
                        }
                    }

                    TlsState::Negotiated(cipher_id_h, cipher_id_l) => {
                        return Poll::Ready(Ok((
                            ClientStream(stream),
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

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
struct SyncTcpStream<'a, 'b> {
    stream: &'a mut OhosTcpStream,
    cx: &'a mut Context<'b>,
}

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
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

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
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

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
struct SyncTcpStream<'a, 'b> {
    stream: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
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

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
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

#[cfg(all(feature = "android", target_os = "android"))]
impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            OhosStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            OhosStream::Tls(conn, stream, state) => match *state {
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
        }
    }
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
impl AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            TokioStream::Tls(conn, stream, state) => match *state {
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
        }
    }
}

#[cfg(all(feature = "android", target_os = "android"))]
impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                Pin::new(stream).poll_flush(cx)
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            AndroidStream::Tcp(stream) | AndroidStream::Tls(stream, _) => {
                Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

#[cfg(all(feature = "ohos", all(target_os = "linux", target_env = "ohos")))]
impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
            OhosStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            OhosStream::Tls(ref mut conn, ref mut stream, _) => {
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            OhosStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            OhosStream::Tls(conn, stream, _) => {
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
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0 {
            OhosStream::Tcp(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
            OhosStream::Tls(ref mut conn, ref mut stream, ref mut state) => {
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
        }
    }
}

#[cfg(not(any(
    all(feature = "android", target_os = "android"),
    all(feature = "ohos", all(target_os = "linux", target_env = "ohos"))
)))]
impl AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().0 {
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().0 {
            TokioStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            TokioStream::Tls(conn, stream, _) => {
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
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut().0 {
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
        }
    }
}

pub enum ErrorKind {
    HandshakeFailure,
    Io,
    Platform,
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

            ErrorKind::Platform => {
                write!(f, "Platform")
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
