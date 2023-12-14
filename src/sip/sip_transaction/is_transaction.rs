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

use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::ffi::log::platform_log;
use crate::sip::sip_message::{build_message_data, SipMessage};
use crate::sip::SipTransport;

use super::server_transaction;
use super::server_transaction::ServerTransactionEvent;

const LOG_TAG: &str = "sip_transaction";

enum State {
    None,
    Proceeding,
    Completed,
    Confirmed,
    Accepted,
    Terminated,
}

pub struct ISTransaction {
    state: Arc<Mutex<(State, Option<SipMessage>, Option<SipMessage>)>>,
    pub message: SipMessage,
    pub to_tag: Arc<Mutex<Option<Vec<u8>>>>,
    pub transport: Arc<SipTransport>,
    transport_function: Box<dyn Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static>,
}

pub enum SendResult {
    None,
    TimerH,
    TimerL,
}

impl ISTransaction {
    pub fn new<F>(message: SipMessage, transport: &Arc<SipTransport>, f: F) -> ISTransaction
    where
        F: Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static,
    {
        ISTransaction {
            state: Arc::new(Mutex::new((State::None, None, None))),
            message,
            to_tag: Arc::new(Mutex::new(None)),
            transport: Arc::clone(transport),
            transport_function: Box::new(f),
        }
    }

    pub fn is_terminated(&self) -> bool {
        let guard = self.state.lock().unwrap();
        match guard.0 {
            State::Terminated => true,
            _ => false,
        }
    }

    /// Returns Ok(('should start timer_h', 'should start timer_l')) on success
    pub fn send_response(&self, resp_message: SipMessage) -> Result<SendResult, &'static str> {
        if let SipMessage::Response(resp_line, _, _) = &resp_message {
            if resp_line.status_code >= 100 && resp_line.status_code < 200 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::None | State::Proceeding => {
                        let data = build_message_data(&resp_message);

                        guard.0 = State::Proceeding;
                        guard.1 = Some(resp_message);

                        platform_log(
                            LOG_TAG,
                            format!("sending IS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::None);
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 200 && resp_line.status_code < 300 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::None | State::Proceeding => {
                        let data = build_message_data(&resp_message);

                        guard.0 = State::Accepted;

                        platform_log(
                            LOG_TAG,
                            format!("sending IS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::TimerL);
                    }
                    State::Accepted => {
                        let data = build_message_data(&resp_message);

                        platform_log(
                            LOG_TAG,
                            format!("sending IS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::None);
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 300 && resp_line.status_code < 700 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::None | State::Proceeding => {
                        let data = build_message_data(&resp_message);

                        guard.0 = State::Completed;
                        guard.2 = Some(resp_message);

                        platform_log(
                            LOG_TAG,
                            format!("sending IS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::TimerH);
                    }
                    _ => {}
                }
            }
        }

        Err("Wrong state")
    }

    pub fn on_retransmission(&self) {
        let guard = self.state.lock().unwrap();
        match guard.0 {
            State::Proceeding => {
                if let Some(message) = &guard.1 {
                    let data = build_message_data(message);

                    platform_log(
                        LOG_TAG,
                        format!(
                            "sending IS re-transmission {}",
                            String::from_utf8_lossy(&data)
                        ),
                    );

                    (self.transport_function)(&self.transport, data);
                }
            }
            State::Completed => {
                if let Some(message) = &guard.2 {
                    let data = build_message_data(message);

                    platform_log(
                        LOG_TAG,
                        format!(
                            "sending IS re-transmission {}",
                            String::from_utf8_lossy(&data)
                        ),
                    );

                    (self.transport_function)(&self.transport, data);
                }
            }
            _ => {}
        }
    }

    /// Returns Ok('should start timer_i') on success
    pub fn on_ack(
        &self,
        tx: &mpsc::Sender<ServerTransactionEvent>,
        rt: &Arc<Runtime>,
    ) -> Result<bool, &'static str> {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Completed => {
                guard.0 = State::Confirmed;
                return Ok(true);
            }
            State::Accepted => {
                let tx = tx.clone();
                rt.spawn(async move {
                    match tx.send(ServerTransactionEvent::Acked).await {
                        Ok(()) => {}
                        Err(e) => {}
                    }
                });
                return Ok(false);
            }
            _ => {}
        }

        Err("Wrong state")
    }

    /// Returns Ok('should start timer_h') on success
    pub fn on_cancel(
        &self,
        tx: &mpsc::Sender<ServerTransactionEvent>,
        rt: &Arc<Runtime>,
    ) -> Result<bool, &'static str> {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::None | State::Proceeding => {
                guard.0 = State::Completed;
                let resp_message = server_transaction::make_response(
                    &self.message,
                    &self.to_tag,
                    487,
                    b"Request Terminated",
                );
                if let Some(resp_message) = resp_message {
                    let data = build_message_data(&resp_message);

                    guard.2 = Some(resp_message);

                    platform_log(
                        LOG_TAG,
                        format!("sending IS response {}", String::from_utf8_lossy(&data)),
                    );

                    (self.transport_function)(&self.transport, data);
                }
                let tx = tx.clone();
                rt.spawn(async move {
                    match tx.send(ServerTransactionEvent::Cancelled).await {
                        Ok(()) => {}
                        Err(e) => {}
                    }
                });
                return Ok(true);
            }
            _ => {}
        }

        Err("Wrong state")
    }

    pub fn on_timer_100(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::None => {
                let resp_message =
                    server_transaction::make_response(&self.message, &self.to_tag, 100, b"Trying");
                if let Some(resp_message) = resp_message {
                    let data = build_message_data(&resp_message);

                    guard.0 = State::Proceeding;

                    platform_log(
                        LOG_TAG,
                        format!("sending IS response {}", String::from_utf8_lossy(&data)),
                    );

                    (self.transport_function)(&self.transport, data);
                }
            }
            _ => {}
        }
    }

    pub fn on_timer_g(&self) {}

    pub fn on_timer_h(&self, tx: mpsc::Sender<ServerTransactionEvent>, rt: &Arc<Runtime>) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Completed => {
                guard.0 = State::Terminated;
                rt.spawn(async move {
                    match tx.send(ServerTransactionEvent::TransportError).await {
                        Ok(()) => {}
                        Err(e) => {}
                    }
                });
            }
            _ => {}
        }
    }

    pub fn on_timer_i(&self) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Confirmed => {
                guard.0 = State::Terminated;
            }
            _ => {}
        }
    }

    pub fn on_timer_l(&self, tx: mpsc::Sender<ServerTransactionEvent>, rt: &Arc<Runtime>) {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Accepted => {
                guard.0 = State::Terminated;
                rt.spawn(async move {
                    match tx.send(ServerTransactionEvent::Completion).await {
                        Ok(()) => {}
                        Err(e) => {}
                    }
                });
            }
            _ => {}
        }
    }
}
