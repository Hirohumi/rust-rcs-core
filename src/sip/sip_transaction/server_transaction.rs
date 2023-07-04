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

use std::io::Read;
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::internet::header::{self, Header};
use crate::internet::header_field::AsHeaderField;
use crate::io::{DynamicChain, Serializable};
use crate::sip::SipTransport;
use crate::util::rand;
// use crate::util::timer::Timer;

use super::super::sip_headers::cseq::AsCSeq;
use super::super::sip_headers::from_to::AsFromTo;
use super::super::sip_headers::from_to::FromTo;
use super::super::sip_headers::via::AsVia;
use super::super::sip_message::SipMessage;
use super::super::sip_message::ACK;
use super::super::sip_message::CANCEL;
use super::super::sip_message::INVITE;

use super::is_transaction;
use super::is_transaction::ISTransaction;
use super::nis_transaction;
use super::nis_transaction::NISTransaction;
use super::T1;

pub enum ServerTransaction {
    IS(ISTransaction),
    NIS(NISTransaction),
}

impl ServerTransaction {
    pub fn transport(&self) -> &Arc<SipTransport> {
        match self {
            ServerTransaction::IS(transaction) => &transaction.transport,
            ServerTransaction::NIS(transaction) => &transaction.transport,
        }
    }

    pub fn message(&self) -> &SipMessage {
        match self {
            ServerTransaction::IS(transaction) => &transaction.message,
            ServerTransaction::NIS(transaction) => &transaction.message,
        }
    }

    pub fn to_tag(&self) -> &Arc<Mutex<Option<Vec<u8>>>> {
        match self {
            ServerTransaction::IS(transaction) => &transaction.to_tag,
            ServerTransaction::NIS(transaction) => &transaction.to_tag,
        }
    }

    pub fn matches(&self, message: &SipMessage) -> bool {
        if let SipMessage::Request(lh_line, Some(lh_headers), _) = Self::message(self) {
            if let SipMessage::Request(rh_line, Some(rh_headers), _) = message {
                let lh_via_header = header::search(lh_headers, b"Via", true);
                let rh_via_header = header::search(rh_headers, b"Via", true);
                if let (Some(lh_via_header), Some(rh_via_header)) = (lh_via_header, rh_via_header) {
                    let lh_via_header_field = lh_via_header.get_value().as_header_field();
                    let rh_via_header_field = rh_via_header.get_value().as_header_field();

                    let lh_via = lh_via_header_field.as_via();
                    let rh_via = rh_via_header_field.as_via();

                    if let (Some(lh_via), Some(rh_via)) = (lh_via, rh_via) {
                        if lh_via.branch != rh_via.branch || lh_via.sent_by != rh_via.sent_by {
                            return false;
                        }

                        if rh_line.method == INVITE || rh_line.method == ACK {
                            if lh_line.method == INVITE {
                                if lh_line.uri != rh_line.uri {
                                    return false;
                                }

                                let lh_from_header = header::search(lh_headers, b"From", true);
                                let rh_from_header = header::search(rh_headers, b"From", true);
                                let lh_to_header = header::search(lh_headers, b"To", true);
                                let rh_to_header = header::search(rh_headers, b"To", true);

                                if let (
                                    Some(lh_from_header),
                                    Some(rh_from_header),
                                    Some(lh_to_header),
                                    Some(rh_to_header),
                                ) = (lh_from_header, rh_from_header, lh_to_header, rh_to_header)
                                {
                                    let lh_from_header_field =
                                        lh_from_header.get_value().as_header_field();
                                    let rh_from_header_field =
                                        rh_from_header.get_value().as_header_field();
                                    let lh_to_header_field =
                                        lh_to_header.get_value().as_header_field();
                                    let rh_to_header_field =
                                        rh_to_header.get_value().as_header_field();

                                    let lh_from = lh_from_header_field.as_from_to();
                                    let rh_from = rh_from_header_field.as_from_to();
                                    let lh_to = lh_to_header_field.as_from_to();
                                    let rh_to = rh_to_header_field.as_from_to();

                                    if let (Some(_), Some(_), Some(_), Some(_)) = (
                                        lh_from.addresses.first(),
                                        rh_from.addresses.first(),
                                        lh_to.addresses.first(),
                                        rh_to.addresses.first(),
                                    ) {
                                        if rh_line.method == INVITE {
                                            if lh_to.tag != rh_to.tag {
                                                return false;
                                            }
                                        } else {
                                            let guard: std::sync::MutexGuard<Option<Vec<u8>>>;
                                            match self {
                                                ServerTransaction::IS(transaction) => {
                                                    guard = transaction.to_tag.lock().unwrap();
                                                }
                                                ServerTransaction::NIS(transaction) => {
                                                    guard = transaction.to_tag.lock().unwrap();
                                                }
                                            }
                                            match (&*guard, rh_to.tag) {
                                                (Some(assigned_to_tag), Some(to_tag)) => {
                                                    if &assigned_to_tag[..] != to_tag {
                                                        return false;
                                                    }
                                                }
                                                (Some(_), None) | (None, Some(_)) => return false,
                                                _ => {}
                                            }
                                        }
                                        let lh_call_id_header =
                                            header::search(lh_headers, b"Call-ID", true);
                                        let rh_call_id_header =
                                            header::search(rh_headers, b"Call-ID", true);
                                        if let (Some(lh_call_id_header), Some(rh_call_id_header)) =
                                            (lh_call_id_header, rh_call_id_header)
                                        {
                                            if lh_call_id_header.get_value()
                                                != rh_call_id_header.get_value()
                                            {
                                                return false;
                                            }
                                            if rh_line.method == INVITE {
                                                let lh_cseq_header =
                                                    header::search(lh_headers, b"CSeq", true);
                                                let rh_cseq_header =
                                                    header::search(rh_headers, b"CSeq", true);
                                                if let (
                                                    Some(lh_cseq_header),
                                                    Some(rh_cseq_header),
                                                ) = (lh_cseq_header, rh_cseq_header)
                                                {
                                                    let lh_cseq_header_field = lh_cseq_header
                                                        .get_value()
                                                        .as_header_field();
                                                    let rh_cseq_header_field = rh_cseq_header
                                                        .get_value()
                                                        .as_header_field();

                                                    let lh_cseq = lh_cseq_header_field.as_cseq();
                                                    let rh_cseq = rh_cseq_header_field.as_cseq();

                                                    if let (Some(lh_cseq), Some(rh_cseq)) =
                                                        (lh_cseq, rh_cseq)
                                                    {
                                                        return lh_cseq.method == rh_cseq.method;
                                                    } else {
                                                        return false;
                                                    }
                                                } else {
                                                    return false;
                                                }
                                            } else {
                                                return true;
                                            }
                                        } else {
                                            return false;
                                        }
                                    } else {
                                        return false;
                                    }
                                } else {
                                    return false;
                                }
                            }
                        } else if rh_line.method == CANCEL {
                            return lh_line.method != ACK && lh_line.method != CANCEL;
                        }

                        return lh_line.method == rh_line.method;
                    }
                }
            }
        }

        false
    }

    pub fn is_terminated(&self) -> bool {
        match self {
            ServerTransaction::IS(transaction) => transaction.is_terminated(),
            ServerTransaction::NIS(transaction) => transaction.is_terminated(),
        }
    }

    pub fn on_timer_g(&self) {
        if let ServerTransaction::IS(transaction) = self {
            transaction.on_timer_g();
        }
    }

    pub fn on_timer_h(&self, tx: mpsc::Sender<ServerTransactionEvent>, rt: &Arc<Runtime>) {
        if let ServerTransaction::IS(transaction) = self {
            transaction.on_timer_h(tx, rt);
        }
    }

    pub fn on_timer_i(&self) {
        if let ServerTransaction::IS(transaction) = self {
            transaction.on_timer_i();
        }
    }

    pub fn on_timer_j(&self) {
        if let ServerTransaction::NIS(transaction) = self {
            transaction.on_timer_j();
        }
    }

    pub fn on_timer_l(&self, tx: mpsc::Sender<ServerTransactionEvent>, rt: &Arc<Runtime>) {
        if let ServerTransaction::IS(transaction) = self {
            transaction.on_timer_l(tx, rt);
        }
    }
}

trait GenerateToTag {
    fn get_assigned_to_tag(&self) -> Option<Vec<u8>>;
}

impl GenerateToTag for Arc<Mutex<Option<Vec<u8>>>> {
    fn get_assigned_to_tag(&self) -> Option<Vec<u8>> {
        let guard = self.lock().unwrap();
        match &*guard {
            Some(tag) => Some(tag.clone()),
            None => None,
        }
    }
}

pub fn make_response(
    request_message: &SipMessage,
    assigned_to_tag: &Arc<Mutex<Option<Vec<u8>>>>,
    status_code: u16,
    reason_phrase: &[u8],
) -> Option<SipMessage> {
    if let SipMessage::Request(_, Some(headers), _) = request_message {
        let via_header = header::search(headers, b"Via", true);
        let call_id_header = header::search(headers, b"Call-ID", true);
        let cseq_header = header::search(headers, b"CSeq", true);
        let from_header = header::search(headers, b"From", true);
        let to_header = header::search(headers, b"To", true);

        if let (
            Some(via_header),
            Some(call_id_header),
            Some(cseq_header),
            Some(from_header),
            Some(to_header),
        ) = (
            via_header,
            call_id_header,
            cseq_header,
            from_header,
            to_header,
        ) {
            let to_header_field = to_header.get_value().as_header_field();

            let to = to_header_field.as_from_to();

            if let Some(_) = to.addresses.first() {
                let mut to_tag: Option<Vec<u8>> = None;

                let mut guard = assigned_to_tag.lock().unwrap();

                match *guard {
                    None => match to.tag {
                        Some(tag) => {
                            let tag = tag.to_vec();
                            let t = tag.clone();
                            *guard = Some(tag);
                            to_tag = Some(t);
                        }
                        None => {
                            if status_code > 100 {
                                let tag = rand::create_raw_alpha_numeric_string(8);
                                let t = tag.clone();
                                *guard = Some(tag);
                                to_tag = Some(t);
                            }
                        }
                    },
                    _ => {}
                }

                let mut message = SipMessage::new_response(status_code, reason_phrase);

                message.add_header(Header::new(b"Via", via_header.get_value().to_vec()));

                message.add_header(Header::new(b"Call-ID", call_id_header.get_value().to_vec()));

                message.add_header(Header::new(b"CSeq", cseq_header.get_value().to_vec()));

                message.add_header(Header::new(b"From", from_header.get_value().to_vec()));

                let resp_to;

                if let Some(to_tag) = &to_tag {
                    resp_to = FromTo {
                        addresses: to.addresses,
                        tag: Some(&to_tag),
                    };
                } else {
                    resp_to = FromTo {
                        addresses: to.addresses,
                        tag: None,
                    };
                }

                let data_size = resp_to.estimated_size();
                let mut to_data = Vec::with_capacity(data_size);
                {
                    let mut readers = Vec::new();
                    resp_to.get_readers(&mut readers);
                    match DynamicChain::new(readers).read_to_end(&mut to_data) {
                        Ok(_) => {}
                        Err(_) => {} // to-do: early failure
                    }
                }

                message.add_header(Header::new(b"To", to_data));

                return Some(message);
            }
        }
    }

    None
}

pub enum ServerTransactionEvent {
    Acked,
    Cancelled,
    Completion,
    TransportError,
}

pub fn send_response(
    transaction: Arc<ServerTransaction>,
    mut resp_message: SipMessage,
    tx: mpsc::Sender<ServerTransactionEvent>,
    rt: &Arc<Runtime>,
    // timer: &Timer,
) {
    if !resp_message.has_body() {
        resp_message.add_header(Header::new("Content-Length", "0"));
    }

    match &*transaction {
        ServerTransaction::IS(t) => {
            if let Ok(result) = t.send_response(resp_message) {
                match result {
                    is_transaction::SendResult::TimerH => {
                        let transaction = Arc::clone(&transaction);
                        let rt_ = Arc::clone(&rt);
                        rt.spawn(async move {
                            sleep(64 * T1).await;
                            transaction.on_timer_h(tx, &rt_);
                        });
                        // timer.schedule(T1 * 64, move || {
                        //     transaction.on_timer_h(&tx);
                        // });
                    }
                    is_transaction::SendResult::TimerL => {
                        let transaction = Arc::clone(&transaction);
                        let rt_ = Arc::clone(&rt);
                        rt.spawn(async move {
                            sleep(64 * T1).await;
                            transaction.on_timer_l(tx, &rt_);
                        });
                        // timer.schedule(T1 * 64, move || {
                        //     transaction.on_timer_l(&tx);
                        // });
                    }
                    _ => {}
                }
            }
        }
        ServerTransaction::NIS(t) => {
            if let Ok(result) = t.send_response(resp_message) {
                match result {
                    nis_transaction::SendResult::TimerJ => {
                        t.on_timer_j(); // to-do: udp
                    }
                    _ => {}
                }
            }
        }
    }
}
