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

use crate::sip::SipTransport;

pub struct HeartbeatTransaction {
    state: Arc<Mutex<bool>>,
    pub transport: Arc<SipTransport>,
    transport_function: Box<dyn Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static>,
    callback: Box<dyn Fn(bool) + Send + Sync>,
}

impl HeartbeatTransaction {
    pub fn new<F, C>(transport: &Arc<SipTransport>, f: F, c: C) -> HeartbeatTransaction
    where
        F: Fn(&Arc<SipTransport>, Vec<u8>) -> bool + Send + Sync + 'static,
        C: Fn(bool) + Send + Sync + 'static,
    {
        HeartbeatTransaction {
            state: Arc::new(Mutex::new(false)),
            transport: Arc::clone(&transport),
            transport_function: Box::new(f),
            callback: Box::new(c),
        }
    }

    pub fn start(&self) {
        (self.transport_function)(&self.transport, b"\r\n".to_vec());
    }

    pub fn on_response(&self) {
        {
            let mut guard = self.state.lock().unwrap();
            if *guard {
                return;
            }
            *guard = true;
        }

        (self.callback)(true);
    }

    pub fn on_timeout(&self) {
        {
            let mut guard = self.state.lock().unwrap();
            if *guard {
                return;
            }
            *guard = true;
        }

        (self.callback)(false);
    }
}
