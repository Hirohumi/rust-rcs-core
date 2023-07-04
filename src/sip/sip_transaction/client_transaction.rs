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

use std::sync::Arc;

use crate::internet::header;
use crate::internet::header_field::AsHeaderField;
use crate::sip::SipTransport;

use super::super::sip_headers::cseq::AsCSeq;
use super::super::sip_headers::via::AsVia;
use super::super::sip_message::SipMessage;

use super::ic_transaction::ICTransaction;
use super::nic_transaction::NICTransaction;

pub enum ClientTransaction {
    IC(ICTransaction),
    NIC(NICTransaction),
}

impl ClientTransaction {
    pub fn transport(&self) -> &Arc<SipTransport> {
        match self {
            ClientTransaction::IC(transaction) => &transaction.transport,
            ClientTransaction::NIC(transaction) => &transaction.transport,
        }
    }

    pub fn message(&self) -> &SipMessage {
        match self {
            ClientTransaction::IC(transaction) => &transaction.message,
            ClientTransaction::NIC(transaction) => &transaction.message,
        }
    }

    pub fn matches(&self, message: &SipMessage) -> bool {
        if let SipMessage::Request(req_line, Some(req_headers), _) = Self::message(self) {
            if let SipMessage::Response(_, Some(resp_headers), _) = message {
                let req_via_header = header::search(req_headers, b"Via", true);
                let resp_via_header = header::search(resp_headers, b"Via", true);
                let resp_cseq_header = header::search(resp_headers, b"CSeq", true);
                if let (Some(req_via_header), Some(resp_via_header), Some(resp_cseq_header)) =
                    (req_via_header, resp_via_header, resp_cseq_header)
                {
                    let req_via_header_field = req_via_header.get_value().as_header_field();
                    let resp_via_header_field = resp_via_header.get_value().as_header_field();
                    let resp_cseq_header_field = resp_cseq_header.get_value().as_header_field();

                    let req_via = req_via_header_field.as_via();
                    let resp_via = resp_via_header_field.as_via();
                    let resp_cseq = resp_cseq_header_field.as_cseq();

                    if let (Some(req_via), Some(resp_via), Some(resp_cseq)) =
                        (req_via, resp_via, resp_cseq)
                    {
                        return req_line.method == resp_cseq.method
                            && req_via.branch == resp_via.branch;
                    }
                }
            }
        }

        false
    }

    pub fn start(&self) {
        match self {
            ClientTransaction::IC(transaction) => transaction.start(),
            ClientTransaction::NIC(transaction) => transaction.start(),
        }
    }

    pub fn on_timer_b(&self) {
        if let ClientTransaction::IC(transaction) = self {
            transaction.on_timer_b();
        }
    }

    pub fn on_timer_d(&self) {
        if let ClientTransaction::IC(transaction) = self {
            transaction.on_timer_d();
        }
    }

    pub fn on_timer_f(&self) {
        if let ClientTransaction::NIC(transaction) = self {
            transaction.on_timer_f();
        }
    }

    pub fn on_timer_k(&self) {
        if let ClientTransaction::NIC(transaction) = self {
            transaction.on_timer_k();
        }
    }

    pub fn on_timer_m(&self) {
        if let ClientTransaction::IC(transaction) = self {
            transaction.on_timer_m();
        }
    }

    /// Returns Ok(('should start timer_d', 'should start timer_m', 'should start timer_k')) on success
    pub fn on_response(&self, message: SipMessage) -> Result<(bool, bool, bool), &'static str> {
        match self {
            ClientTransaction::IC(transaction) => match transaction.on_response(message) {
                Ok((timer_d, timer_m)) => Ok((timer_d, timer_m, false)),
                Err(e) => Err(e),
            },
            ClientTransaction::NIC(transaction) => match transaction.on_response(message) {
                Ok(timer_k) => Ok((false, false, timer_k)),
                Err(e) => Err(e),
            },
        }
    }

    pub fn on_transport_error(&self) {}
}

pub trait ClientTransactionCallbacks {
    fn on_provisional_response(&self, message: SipMessage);
    fn on_final_response(&self, message: SipMessage);
    fn on_transport_error(&self);
}

pub struct ClientTransactionNilCallbacks {}

impl ClientTransactionCallbacks for ClientTransactionNilCallbacks {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, _message: SipMessage) {}

    fn on_transport_error(&self) {}
}
