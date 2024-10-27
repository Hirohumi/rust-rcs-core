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

use std::fmt::Debug;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::ffi::log::platform_log;
use crate::sip::sip_parser::SipParser;

use super::sip_transaction::heartbeat_transaction::HeartbeatTransaction;
use super::{ClientTransaction, SipMessage};

pub enum TransportMessage {
    Incoming(Arc<SipTransport>, SipMessage),
    Outgoing(Arc<ClientTransaction>),
    Heartbeat(Arc<HeartbeatTransaction>),
    Drop(Arc<SipTransport>),
    Exit,
}

impl Debug for TransportMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incoming(arg0, arg1) => {
                f.debug_tuple("Incoming").field(arg0).field(arg1).finish()
            }
            Self::Outgoing(_) => write!(f, "Outgoing"),
            Self::Heartbeat(_) => write!(f, "Heartbeat"),
            Self::Drop(arg0) => f.debug_tuple("Drop").field(arg0).finish(),
            Self::Exit => write!(f, "Exit"),
        }
    }
}

// pub trait SipTransportImpl: Transport + Read + Write + Closable + Send {}

const LOG_TAG: &str = "sip";

#[derive(Debug)]
pub enum SipTransportType {
    UDP,
    TCP,
    TLS,
}

#[derive(Debug)]
pub struct SipTransport {
    pub transport_address: String,
    pub transport_type: SipTransportType,
}

impl SipTransport {
    pub fn new<T>(transport_address: String, transport_type: SipTransportType) -> SipTransport {
        SipTransport {
            transport_address,
            transport_type,
        }
    }

    pub fn get_via(&self) -> String {
        match self.transport_type {
            SipTransportType::UDP => format!("SIP/2.0/UDP {}", self.transport_address),
            SipTransportType::TCP => format!("SIP/2.0/TCP {}", self.transport_address),
            SipTransportType::TLS => format!("SIP/2.0/TLS {}", self.transport_address),
        }
    }

    pub fn get_contact_transport_type(&self) -> String {
        match self.transport_type {
            SipTransportType::UDP => String::from("udp"),
            SipTransportType::TCP => String::from("tcp"),
            SipTransportType::TLS => String::from("tcp"),
        }
    }
}

pub fn setup_sip_transport<T, F>(
    transport: &Arc<SipTransport>,
    t: T,
    tm_ctrl_itf: mpsc::Sender<TransportMessage>,
    rt: Arc<Runtime>,
    exit_callback: F,
) -> mpsc::Sender<Option<Vec<u8>>>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
    F: FnOnce() + Send + 'static,
{
    let (mut rh, mut wh) = tokio::io::split(t);

    let (tx, mut rx): (
        mpsc::Sender<Option<Vec<u8>>>,
        mpsc::Receiver<Option<Vec<u8>>>,
    ) = mpsc::channel(8);

    let transport = Arc::clone(&transport);

    rt.spawn(async move {
        let mut parser = SipParser::new();
        let mut data: [u8; 4096] = [0; 4096];
        'read: while let Ok(size) = rh.read(&mut data).await {
            platform_log(LOG_TAG, format!("sip_transport read {} bytes", size));
            if size > 0 {
                let mut i = 0;
                while i < size {
                    let j = if i + 512 < size { i + 512 } else { size };
                    platform_log(LOG_TAG, format!("{:?}", std::str::from_utf8(&data[i..j])));
                    i = i + 512;
                }
                parser.feed(&data[..size]);
                loop {
                    match parser.produce() {
                        Ok(message) => {
                            if let Some(message) = message {
                                platform_log(LOG_TAG, "on complete message");
                                let transport = Arc::clone(&transport);
                                match tm_ctrl_itf
                                    .send(TransportMessage::Incoming(transport, message))
                                    .await
                                {
                                    Ok(()) => {}
                                    Err(e) => {
                                        platform_log(
                                            LOG_TAG,
                                            format!("failed to handle transaction event {:?}", e),
                                        );
                                    }
                                }
                            } else {
                                platform_log(LOG_TAG, "incomplete message, continue");
                                continue 'read;
                            }
                        }
                        Err(e) => {
                            platform_log(
                                LOG_TAG,
                                format!("sip parsing error for transport {:?}: {}", transport, e),
                            );
                            break 'read;
                        }
                    }
                }
            } else {
                break;
            }
        }

        platform_log(LOG_TAG, "read handle exit");

        match tm_ctrl_itf.send(TransportMessage::Drop(transport)).await {
            Ok(()) => {}
            Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
        }

        exit_callback();
    });

    rt.spawn(async move {
        'thread: loop {
            let mut written = 0;
            if let Some(Some(data)) = rx.recv().await {
                platform_log(
                    LOG_TAG,
                    format!("sip_transport sending {} bytes of data", data.len()),
                );
                while let Ok(size) = wh.write(&data[written..]).await {
                    platform_log(LOG_TAG, format!("sip_transport {} bytes written", size));
                    if size > 0 {
                        written = written + size;
                        if written == data.len() {
                            continue 'thread;
                        }
                        continue;
                    }
                }
            } else {
                break;
            }

            platform_log(LOG_TAG, "write handle exit");
        }

        match wh.shutdown().await {
            Ok(()) => {
                platform_log(LOG_TAG, "write handle shutdown ok");
            }

            Err(e) => {
                platform_log(LOG_TAG, format!("write handle shutdown error {}", e));
            }
        }
    });

    tx
}
