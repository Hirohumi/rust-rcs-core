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
use crate::sip::sip_message::build_message_data;
use crate::sip::SipTransport;

use super::super::sip_message::SipMessage;

use super::client_transaction::ClientTransactionCallbacks;

const LOG_TAG: &str = "sip_transaction";

enum State {
    None,
    Trying,
    Proceeding,
    Completed,
    Terminated,
}

pub struct NICTransaction {
    state: Arc<Mutex<State>>,
    pub message: SipMessage,
    pub transport: Arc<SipTransport>,
    transport_function: Box<dyn Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync>,
    callbacks: Box<dyn ClientTransactionCallbacks + Send + Sync>,
}

impl NICTransaction {
    pub fn new<F, C>(
        message: SipMessage,
        transport: &Arc<SipTransport>,
        f: F,
        c: C,
    ) -> NICTransaction
    where
        F: Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static,
        C: ClientTransactionCallbacks + Send + Sync + 'static,
    {
        NICTransaction {
            state: Arc::new(Mutex::new(State::None)),
            message,
            transport: Arc::clone(transport),
            transport_function: Box::new(f),
            callbacks: Box::new(c),
        }
    }

    pub fn is_terminated(&self) -> bool {
        let guard = self.state.lock().unwrap();
        match *guard {
            State::Terminated => true,
            _ => false,
        }
    }

    fn perform_send(&self, message: &SipMessage) {
        let data = build_message_data(message);

        platform_log(
            LOG_TAG,
            format!("NIC send message {}", String::from_utf8_lossy(&data)),
        );

        (self.transport_function)(&self.transport, data);
    }

    pub fn start(&self) {
        let mut guard = self.state.lock().unwrap();
        match *guard {
            State::None => {
                *guard = State::Trying;
                self.perform_send(&self.message);
                // to-do: start timer_e for unreliable transport
            }
            _ => {}
        }
    }

    /// Returns Ok('should restart timer_e at doubling T1', 'should restart timer_e at T2') on success
    pub fn on_timer_e(&self) -> Result<(bool, bool), &'static str> {
        let guard = self.state.lock().unwrap();
        match *guard {
            State::Trying => {
                self.perform_send(&self.message);
                return Ok((true, false));
            }
            State::Proceeding => {
                self.perform_send(&self.message);
                return Ok((false, true));
            }
            _ => {}
        }

        Err("Wrong state")
    }

    pub fn on_timer_f(&self) {
        let mut guard = self.state.lock().unwrap();
        match *guard {
            State::Trying | State::Proceeding => {
                *guard = State::Terminated;
                self.callbacks.on_transport_error();
            }
            _ => {}
        }
    }

    pub fn on_timer_k(&self) {
        let mut guard = self.state.lock().unwrap();
        match *guard {
            State::Completed => {
                *guard = State::Terminated;
            }
            _ => {}
        }
    }

    /// Returns Ok('should start timer_k') on success
    pub fn on_response(&self, resp_message: SipMessage) -> Result<bool, &'static str> {
        if let SipMessage::Response(resp_line, _, _) = &resp_message {
            if resp_line.status_code >= 100 && resp_line.status_code < 200 {
                let mut guard = self.state.lock().unwrap();
                match *guard {
                    State::Trying => {
                        *guard = State::Proceeding;
                        self.callbacks.on_provisional_response(resp_message);
                        return Ok(false);
                    }
                    _ => {}
                }
            } else if resp_line.status_code >= 200 && resp_line.status_code < 700 {
                let mut guard = self.state.lock().unwrap();
                match *guard {
                    State::Trying | State::Proceeding => {
                        *guard = State::Completed;
                        self.callbacks.on_final_response(resp_message);
                        return Ok(true);
                    }
                    _ => {}
                }
            }
        }

        Err("Wrong state")
    }
}
