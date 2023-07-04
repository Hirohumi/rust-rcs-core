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

use crate::ffi::log::platform_log;
use crate::sip::sip_message::{build_message_data, SipMessage};
use crate::sip::SipTransport;

const LOG_TAG: &str = "sip_transaction";

enum State {
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

pub struct NISTransaction {
    state: Arc<Mutex<(State, Option<SipMessage>, Option<SipMessage>)>>,
    pub message: SipMessage,
    pub to_tag: Arc<Mutex<Option<Vec<u8>>>>,
    pub transport: Arc<SipTransport>,
    transport_function: Box<dyn Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static>,
}

pub enum SendResult {
    None,
    TimerJ,
}

impl NISTransaction {
    pub fn new<F>(message: SipMessage, transport: &Arc<SipTransport>, f: F) -> NISTransaction
    where
        F: Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static,
    {
        NISTransaction {
            state: Arc::new(Mutex::new((State::Trying, None, None))),
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

    // Returns Ok('should start timer_j') on success
    pub fn send_response(&self, resp_message: SipMessage) -> Result<SendResult, &'static str> {
        if let SipMessage::Response(resp_line, _, _) = &resp_message {
            if resp_line.status_code >= 100 && resp_line.status_code < 200 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::Trying => {
                        let data = build_message_data(&resp_message);

                        guard.0 = State::Proceeding;
                        guard.1 = Some(resp_message);

                        platform_log(
                            LOG_TAG,
                            format!("sending NIS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::None);
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 200 && resp_line.status_code < 700 {
                let mut guard = self.state.lock().unwrap();
                match guard.0 {
                    State::Trying | State::Proceeding => {
                        let data = build_message_data(&resp_message);

                        guard.0 = State::Completed;
                        guard.2 = Some(resp_message);

                        platform_log(
                            LOG_TAG,
                            format!("sending NIS response {}", String::from_utf8_lossy(&data)),
                        );

                        (self.transport_function)(&self.transport, data);
                        return Ok(SendResult::TimerJ);
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
                            "sending NIS re-transmission {}",
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
                            "sending NIS re-transmission {}",
                            String::from_utf8_lossy(&data)
                        ),
                    );

                    (self.transport_function)(&self.transport, data);
                }
            }
            _ => {}
        }
    }

    pub fn on_timer_j(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        match guard.0 {
            State::Completed => {
                guard.0 = State::Terminated;
                return true;
            }
            _ => {}
        }
        false
    }
}
