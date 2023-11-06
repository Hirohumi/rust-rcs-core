use std::{
    io,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::ffi::sock::{
    cipher_suite_get_yy, cipher_suite_get_zz, close_socket, create_socket, get_socket_info,
    get_socket_local_address, get_socket_local_port, get_socket_session_cipher_suite, read_socket,
    socket_connect, socket_finish_connect, socket_finish_handshake, socket_start_handshake,
    write_socket, SocketCHandleWrapper, SocketEventReceiverHandle,
};

pub struct AndroidTcpStream {
    pub(crate) socket: SocketCHandleWrapper,
    pub(crate) event_receiver: SocketEventReceiverHandle,
}

impl AndroidTcpStream {
    pub fn create(tls: bool, host_name: &str) -> io::Result<AndroidTcpStream> {
        let (socket, event_receiver) = create_socket(tls, host_name)?;
        Ok(AndroidTcpStream {
            socket,
            event_receiver,
        })
    }

    pub fn connect(self, ip: IpAddr, port: u16) -> io::Result<ConnectTask> {
        let remote_ip = ip.to_string();
        socket_connect(&self.socket, &remote_ip, port)?;
        Ok(ConnectTask { stream: Some(self) })
    }

    pub fn start_handshake(&self) -> io::Result<()> {
        socket_start_handshake(&self.socket)
    }

    pub fn poll_handshake(&self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match socket_finish_handshake(&self.socket) {
            Ok(()) => Poll::Ready(Ok(())),

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => Poll::Pending,

                _ => Poll::Ready(Err(e)),
            },
        }
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
        let task = self.get_mut();
        match task.stream.take() {
            Some(stream) => match socket_finish_connect(&stream.socket) {
                Ok(()) => Poll::Ready(Ok(stream)),

                Err(e) => match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        task.stream.replace(stream);
                        Poll::Pending
                    }

                    _ => Poll::Ready(Err(e)),
                },
            },

            None => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
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

        match read_socket(&stream.socket, buffer) {
            Ok(r) => {
                buf.advance(r);
                return Poll::Ready(Ok(()));
            }

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    let waker = cx.waker().clone();
                    {
                        let mut guard = stream.event_receiver.read_waker.lock().unwrap();
                        guard.replace(waker);
                    }
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

        match write_socket(&stream.socket, buf) {
            Ok(r) => {
                return Poll::Ready(Ok(r));
            }

            Err(e) => match e.kind() {
                io::ErrorKind::WouldBlock => {
                    let waker = cx.waker().clone();
                    {
                        let mut guard = stream.event_receiver.write_waker.lock().unwrap();
                        guard.replace(waker);
                    }
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

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let stream = self.get_mut();
        close_socket(&stream.socket);
        Poll::Ready(Ok(()))
    }
}

unsafe impl Send for AndroidTcpStream {}