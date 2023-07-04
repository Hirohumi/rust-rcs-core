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

use crate::ffi::log::platform_log;
use crate::internet::header::Header;
use crate::internet::header::{self, HeaderSearch};
use crate::internet::header_field::AsHeaderField;
use crate::internet::header_field::HeaderField;
use crate::internet::name_addr::AsNameAddr;
use crate::internet::uri::AsURI;

use crate::io::{DynamicChain, Serializable};

use crate::sip::sip_headers::cseq::AsCSeq;
use crate::sip::sip_headers::cseq::CSeq;
use crate::sip::sip_headers::from_to::AsFromTo;
use crate::sip::sip_headers::from_to::FromTo;
use crate::sip::sip_message::SipMessage;
use crate::sip::sip_message::ACK;
use crate::sip::sip_message::CANCEL;
use crate::sip::sip_transaction::server_transaction;
use crate::sip::sip_transaction::server_transaction::ServerTransaction;
use crate::sip::sip_transaction::server_transaction::ServerTransactionEvent;

// use crate::util::timer::Timer;

const LOG_TAG: &str = "sip";

pub enum SipDialogEvent {
    Ack(Arc<ServerTransaction>),
    MidDialogRequest(),
    Terminate(),
}

enum State {
    Early(
        Vec<Arc<dyn SipDialogEventCallbacks + Send + Sync>>,
        Option<Box<dyn FnOnce(Arc<SipDialog>) + Send + Sync>>,
    ),
    Confirmed(
        Vec<Arc<dyn SipDialogEventCallbacks + Send + Sync>>,
        Option<Box<dyn FnOnce(Arc<SipDialog>) + Send + Sync>>,
    ),
    Completed, // to-do: Now when do we send BYE?
    Terminated,
}

// to-do: use channel to communicate back a real sip-message so we don't have to pass timers around
//  also, a Event object would better suite tokio architecture
pub trait SipDialogEventCallbacks {
    fn on_ack(&self, transaction: &Arc<ServerTransaction>);
    fn on_new_request(
        &self,
        transaction: Arc<ServerTransaction>,
        tx: mpsc::Sender<ServerTransactionEvent>,
        // timer: &Timer,
        rt: &Arc<Runtime>,
    ) -> Option<(u16, bool)>;
    fn on_terminating_request(&self, message: &SipMessage); /* mostly BYE */
    fn on_terminating_response(&self, message: &SipMessage); /* this is where other user leg crashes a dialog with a (likely legal) request */
}

#[derive(PartialEq)]
pub struct SipDialogIdentifier<'a> {
    pub call_id: &'a [u8],
    pub local_tag: &'a [u8],
    pub remote_tag: &'a [u8],
}

pub struct SipDialog {
    state: Arc<Mutex<State>>,

    call_id: Vec<u8>,

    local_seq: Arc<Mutex<Option<u32>>>,
    local_uri: Vec<u8>,
    local_tag: Vec<u8>,

    remote_seq: Arc<Mutex<Option<u32>>>,
    remote_uri: Vec<u8>,
    remote_tag: Vec<u8>,
    remote_target: Arc<Mutex<Vec<u8>>>,

    route_set: Arc<Mutex<Vec<Vec<u8>>>>,

    // message_rx: mpsc::Receiver<SipMessage>,

    // transaction_rx: mpsc::Receiver<(
    //     Arc<ServerTransaction>,
    //     mpsc::Sender<ServerTransactionEvent>,
    //     mpsc::Receiver<ServerTransactionEvent>, // to-do: should be retained by user ?
    // )>,
    // users: Arc<
    //     Mutex<(
    //         i64,
    //         Vec<(i64, Box<dyn SipDialogEventCallbacks + Send + Sync>)>,
    //     )>,
    // >,

    // on_last_user_removed: Box<dyn Fn(Arc<SipDialog>) + Send + Sync>,

    // dialog_users: Arc<Mutex<(Vec<Arc<dyn SipDialogEventCallbacks + Send + Sync>>, Option<Box<dyn FnOnce(Arc<SipDialog>) + Send + Sync>>)>>,
    ongoing_transactions:
        Arc<Mutex<Vec<(Arc<ServerTransaction>, mpsc::Sender<ServerTransactionEvent>)>>>, // to-do: 禁止套娃
}

impl SipDialog {
    fn try_new<T>(
        req_headers: &Vec<Header>,
        resp_message: &SipMessage,
        as_uac: bool,
        on_last_user_removed: T,
    ) -> Result<SipDialog, &'static str>
    where
        T: FnOnce(Arc<SipDialog>) + Send + Sync + 'static,
    {
        if let SipMessage::Response(resp_line, Some(resp_headers), _) = resp_message {
            let req_cseq_header = header::search(req_headers, b"CSeq", true);
            let req_call_id_header = header::search(req_headers, b"Call-ID", true);
            let req_from_header = header::search(req_headers, b"From", true);

            let resp_to_header = header::search(resp_headers, b"To", true);

            let contact_header;
            if as_uac {
                contact_header = header::search(resp_headers, b"Contact", true);
            } else {
                contact_header = header::search(req_headers, b"Contact", true);
            }

            if let (
                Some(req_cseq_header),
                Some(req_call_id_header),
                Some(req_from_header),
                Some(resp_to_header),
                Some(contact_header),
            ) = (
                req_cseq_header,
                req_call_id_header,
                req_from_header,
                resp_to_header,
                contact_header,
            ) {
                let req_cseq_header_field = req_cseq_header.get_value().as_header_field();
                let req_cseq = req_cseq_header_field.as_cseq();
                let req_from_header_field = req_from_header.get_value().as_header_field();
                let req_from = req_from_header_field.as_from_to();
                let resp_to_header_field = resp_to_header.get_value().as_header_field();
                let resp_to = resp_to_header_field.as_from_to();
                let contact_addresses = contact_header.get_value().as_name_addresses();

                if let (Some(req_cseq), Some(req_from_tag), Some(resp_to_tag)) =
                    (req_cseq, req_from.tag, resp_to.tag)
                {
                    let req_from_address = req_from.addresses.first();
                    let resp_to_address = resp_to.addresses.first();
                    let contact_address = contact_addresses.first();

                    if let (Some(req_from_address), Some(resp_to_address), Some(contact_address)) =
                        (req_from_address, resp_to_address, contact_address)
                    {
                        if let (Some(req_from_uri_part), Some(resp_to_uri_part)) =
                            (&req_from_address.uri_part, &resp_to_address.uri_part)
                        {
                            if let Some(uri_part) = &contact_address.uri_part {
                                let data_size = uri_part.estimated_size();
                                let mut data = Vec::with_capacity(data_size);
                                {
                                    let mut readers = Vec::new();
                                    uri_part.get_readers(&mut readers);
                                    match DynamicChain::new(readers).read_to_end(&mut data) {
                                        Ok(_) => {}
                                        Err(_) => {} // to-do: early failure
                                    }
                                }

                                let remote_target = data;

                                let state = if resp_line.status_code >= 100
                                    && resp_line.status_code < 200
                                {
                                    State::Early(Vec::new(), Some(Box::new(on_last_user_removed)))
                                } else {
                                    State::Confirmed(
                                        Vec::new(),
                                        Some(Box::new(on_last_user_removed)),
                                    )
                                };

                                let mut route_set = Vec::new();

                                if as_uac {
                                    let mut iter = resp_headers.iter();
                                    while let Some(position) =
                                        iter.position(|h| h.get_name() == b"Record-Route")
                                    {
                                        let record_route_header = &resp_headers[position];
                                        route_set.push(record_route_header.get_value().to_vec());
                                    }
                                } else {
                                    let mut iter = req_headers.iter();
                                    while let Some(position) =
                                        iter.position(|h| h.get_name() == b"Record-Route")
                                    {
                                        let record_route_header = &req_headers[position];
                                        route_set.push(record_route_header.get_value().to_vec());
                                    }
                                }

                                // let (req_from_uri, _) = req_from_uri_part;
                                // let (resp_to_uri, _) = resp_to_uri_part;

                                return Ok(SipDialog {
                                    state: Arc::new(Mutex::new(state)),

                                    call_id: req_call_id_header.get_value().to_vec(),

                                    local_seq: if as_uac {
                                        Arc::new(Mutex::new(Some(req_cseq.seq)))
                                    } else {
                                        Arc::new(Mutex::new(None))
                                    },

                                    local_uri: req_from_uri_part.uri.to_vec(),
                                    local_tag: req_from_tag.to_vec(),

                                    remote_seq: if as_uac {
                                        Arc::new(Mutex::new(None))
                                    } else {
                                        Arc::new(Mutex::new(Some(req_cseq.seq)))
                                    },

                                    remote_uri: resp_to_uri_part.uri.to_vec(),
                                    remote_tag: resp_to_tag.to_vec(),

                                    remote_target: Arc::new(Mutex::new(remote_target)),

                                    route_set: Arc::new(Mutex::new(route_set)),

                                    // users: Arc::new(Mutex::new((0, Vec::new()))),

                                    // on_last_user_removed: Box::new(on_last_user_removed),

                                    // dialog_users: Arc::new(Mutex::new((Vec::new(), Some(Box::new(on_last_user_removed))))),
                                    ongoing_transactions: Arc::new(Mutex::new(Vec::new())),
                                });
                            }
                        }
                    }
                }
            }
        }

        Err("Missing header information")
    }

    pub fn try_new_as_uac<T>(
        req_headers: &Vec<Header>,
        resp_message: &SipMessage,
        on_last_user_removed: T, // to-do: re-write to async style
    ) -> Result<SipDialog, &'static str>
    where
        T: Fn(Arc<SipDialog>) + Send + Sync + 'static,
    {
        Self::try_new(req_headers, resp_message, true, on_last_user_removed)
    }

    pub fn try_new_as_uas<T>(
        req_message: &SipMessage,
        resp_message: &SipMessage,
        on_last_user_removed: T, // to-do: re-write to async style
    ) -> Result<SipDialog, &'static str>
    where
        T: Fn(Arc<SipDialog>) + Send + Sync + 'static,
    {
        if let SipMessage::Request(_, Some(req_headers), _) = req_message {
            Self::try_new(req_headers, resp_message, false, on_last_user_removed)
        } else {
            Err("Missing header information")
        }
    }

    pub fn dialog_identifier(&self) -> SipDialogIdentifier {
        SipDialogIdentifier {
            call_id: &self.call_id,
            local_tag: &self.local_tag,
            remote_tag: &self.remote_tag,
        }
    }

    pub fn confirm(&self) {
        let mut guard = self.state.lock().unwrap();
        if let State::Early(dialog_users, on_dispose) = &mut *guard {
            let mut dialog_users_ = Vec::new();
            dialog_users_.append(dialog_users);
            let on_dispose_ = on_dispose.take();
            *guard = State::Confirmed(dialog_users_, on_dispose_);
        }
    }

    // pub fn register_user<T>(&self, callbacks: T) -> i64
    // where
    //     T: SipDialogEventCallbacks + Send + Sync + 'static,
    // {
    //     let mut guard = self.users.lock().unwrap();
    //     let id = i64::wrapping_add(guard.0, 1);
    //     guard.0 = id;
    //     guard.1.push((id, Box::new(callbacks)));
    //     id
    // }

    pub fn register_user<T>(&self, callbacks: T) -> Arc<T>
    where
        T: SipDialogEventCallbacks + Send + Sync + 'static,
    {
        let callbacks = Arc::new(callbacks);
        let callbacks_ = Arc::clone(&callbacks);
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            State::Early(dialog_users, _) | State::Confirmed(dialog_users, _) => {
                dialog_users.push(callbacks_);
            }
            _ => {}
        }
        callbacks
    }

    // pub fn unregister_user(&self, id: i64) -> bool {
    //     let mut guard = self.users.lock().unwrap();
    //     let mut i = 0;
    //     while i < guard.1.len() {
    //         let (lh_id, _) = &guard.1[i];
    //         if *lh_id == id {
    //             guard.1.swap_remove(i);
    //             break;
    //         }
    //         i = i + 1;
    //     }

    //     if guard.1.len() == 0 {
    //         let mut state_guard = self.state.lock().unwrap();
    //         match *state_guard {
    //             State::Early => {
    //                 *state_guard = State::Completed;
    //             }
    //             State::Confirmed => {
    //                 *state_guard = State::Completed;
    //                 return true;
    //             }
    //             _ => {}
    //         }
    //     }

    //     false
    // }

    pub fn unregister_user(
        &self,
        callbacks: &Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    ) -> Option<Box<dyn FnOnce(Arc<SipDialog>) + Send + Sync>> {
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            State::Early(dialog_users, on_dispose) | State::Confirmed(dialog_users, on_dispose) => {
                if let Some(idx) = dialog_users
                    .iter()
                    .position(|callback| Arc::ptr_eq(callback, callbacks))
                {
                    dialog_users.swap_remove(idx);
                    if dialog_users.is_empty() {
                        if let Some(on_dispose) = on_dispose.take() {
                            *guard = State::Completed;
                            return Some(on_dispose);
                        }
                    }
                }
            }
            _ => {}
        }

        None
    }

    // pub fn call_last_user_removed_callback(&self, dialog: Arc<SipDialog>) {
    //     (self.on_last_user_removed)(dialog);
    // }

    pub fn register_transaction(
        &self,
        transaction: (
            Arc<ServerTransaction>,
            mpsc::Sender<ServerTransactionEvent>,
            mpsc::Receiver<ServerTransactionEvent>,
        ),
    ) {
    }

    pub fn remote_seq(&self) -> &Arc<Mutex<Option<u32>>> {
        &self.remote_seq
    }

    pub fn on_ack(&self, transaction: &Arc<ServerTransaction>) {
        let guard = self.state.lock().unwrap();
        match &*guard {
            State::Early(dialog_users, _) | State::Confirmed(dialog_users, _) => {
                for callback in dialog_users {
                    callback.on_ack(transaction);
                }
            }
            _ => {}
        }
    }

    fn terminate_transactions(&self, rt: &Arc<Runtime>) {
        let mut guard = self.ongoing_transactions.lock().unwrap();
        for (transaction, tx) in &*guard {
            let message = transaction.message();

            if let Some(resp_message) = server_transaction::make_response(
                message,
                transaction.to_tag(),
                487,
                b"Request Terminated",
            ) {
                server_transaction::send_response(
                    Arc::clone(transaction),
                    resp_message,
                    tx.clone(),
                    // &timer,
                    rt,
                );
            }
        }

        (*guard).clear();
    }

    pub fn on_request(
        &self,
        transaction: &Arc<ServerTransaction>,
        tx: mpsc::Sender<ServerTransactionEvent>,
        // timer: &Timer,
        rt: &Arc<Runtime>,
        seq_guard: &mut std::sync::MutexGuard<Option<u32>>,
        message_seq: u32,
    ) -> Option<Box<dyn FnOnce(Arc<SipDialog>) + Send + Sync>> {
        platform_log(LOG_TAG, "sip dialog on request");

        let mut handled = false;

        let mut res = None;

        // let mut guard = self.users.lock().unwrap();
        let mut guard = self.state.lock().unwrap();

        match &mut *guard {
            State::Early(dialog_users, on_dispose) | State::Confirmed(dialog_users, on_dispose) => {
                let mut i = 0;
                for callback in &mut *dialog_users {
                    if let Some((status_code, terminated)) =
                        callback.on_new_request(Arc::clone(transaction), tx.clone(), rt)
                    {
                        handled = true;

                        if status_code >= 100 && status_code < 200 {
                            (*self.ongoing_transactions.lock().unwrap())
                                .push((Arc::clone(transaction), tx.clone()));
                        } else {
                            **seq_guard = Some(message_seq);
                            let message = transaction.message();
                            if let Some(headers) = message.headers() {
                                if let Some(contact_header) =
                                    header::search(headers, b"Contact", true)
                                {
                                    let contact_addresses =
                                        contact_header.get_value().as_name_addresses();
                                    let contact_address = contact_addresses.first();
                                    if let Some(contact_address) = contact_address {
                                        if let Some(uri_part) = &contact_address.uri_part {
                                            let data_size = uri_part.estimated_size();
                                            let mut data = Vec::with_capacity(data_size);
                                            {
                                                let mut readers = Vec::new();
                                                uri_part.get_readers(&mut readers);
                                                match DynamicChain::new(readers)
                                                    .read_to_end(&mut data)
                                                {
                                                    Ok(_) => {}
                                                    Err(_) => {} // to-do: early failure
                                                }
                                            }

                                            *self.remote_target.lock().unwrap() = data;
                                        }
                                    }
                                }
                            }
                        }

                        if terminated {
                            dialog_users.swap_remove(i);

                            if dialog_users.is_empty() {
                                res = on_dispose.take();
                                *guard = State::Terminated;

                                self.terminate_transactions(rt);
                            }
                        }

                        break;
                    }

                    i += 1;
                }
            }
            State::Completed => {
                todo!()
            }
            _ => {}
        }

        // let mut i = 0;

        // while i < guard.1.len() {
        //     let (_, callback) = &guard.1[i];
        //     if let Some((status_code, terminated)) =
        //         callback.on_new_request(Arc::clone(transaction), tx.clone(), rt)
        //     {
        //         handled = true;

        //         if status_code >= 100 && status_code < 200 {
        //             (*self.ongoing_transactions.lock().unwrap())
        //                 .push((Arc::clone(transaction), tx.clone()));
        //         } else {
        //             **seq_guard = Some(message_seq);
        //             let message = transaction.message();
        //             if let Some(headers) = message.headers() {
        //                 if let Some(contact_header) = header::search(headers, b"Contact", true) {
        //                     let contact_addresses = contact_header.get_value().as_name_addresses();
        //                     let contact_address = contact_addresses.first();
        //                     if let Some(contact_address) = contact_address {
        //                         if let Some(uri_part) = &contact_address.uri_part {
        //                             let data_size = uri_part.estimated_size();
        //                             let mut data = Vec::with_capacity(data_size);
        //                             {
        //                                 let mut readers = Vec::new();
        //                                 uri_part.get_readers(&mut readers);
        //                                 match DynamicChain::new(readers).read_to_end(&mut data) {
        //                                     Ok(_) => {}
        //                                     Err(_) => {} // to-do: early failure
        //                                 }
        //                             }

        //                             *self.remote_target.lock().unwrap() = data;
        //                         }
        //                     }
        //                 }
        //             }
        //         }

        //         if terminated {
        //             guard.1.swap_remove(i);
        //         }

        //         break;
        //     }

        //     i = i + 1;
        // }

        // if guard.1.len() == 0 {
        //     let mut guard = self.state.lock().unwrap();
        //     match *guard {
        //         State::Early | State::Confirmed | State::Completed => {
        //             *guard = State::Terminated;
        //             self.terminate_transactions(rt);
        //         }
        //         _ => {}
        //     }
        // }

        if !handled {
            let message = transaction.message();

            if let Some(resp_message) = server_transaction::make_response(
                message,
                transaction.to_tag(),
                488,
                b"Not Acceptable Here",
            ) {
                server_transaction::send_response(
                    Arc::clone(transaction),
                    resp_message,
                    tx,
                    // &timer,
                    &rt,
                );
            }
        }

        res
    }

    // pub fn on_terminating_request(&self, message: &SipMessage, rt: &Arc<Runtime>) {
    //     let mut guard = self.state.lock().unwrap();
    //     match *guard {
    //         State::Early | State::Confirmed | State::Completed => {
    //             *guard = State::Terminated;

    //             let mut guard = self.users.lock().unwrap();
    //             for (_, callback) in &guard.1 {
    //                 callback.on_terminating_request(message);
    //             }
    //             guard.1.clear();

    //             self.terminate_transactions(rt);
    //         }
    //         _ => {}
    //     }
    // }

    pub fn on_terminating_request(&self, message: &SipMessage, rt: &Arc<Runtime>) {
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            State::Early(dialog_users, on_dispose) | State::Confirmed(dialog_users, on_dispose) => {
                for callback in dialog_users {
                    callback.on_terminating_request(message);
                }
                *guard = State::Terminated;
            }
            State::Completed => {
                *guard = State::Terminated;
            }
            _ => {}
        }
    }

    // pub fn on_terminating_response(&self, message: &SipMessage, rt: &Arc<Runtime>) {
    //     let mut guard = self.state.lock().unwrap();
    //     match *guard {
    //         State::Early | State::Confirmed | State::Completed => {
    //             *guard = State::Terminated;

    //             let mut guard = self.users.lock().unwrap();
    //             for (_, callback) in &guard.1 {
    //                 callback.on_terminating_response(message);
    //             }
    //             guard.1.clear();

    //             self.terminate_transactions(rt);
    //         }
    //         _ => {}
    //     }
    // }

    pub fn on_terminating_response(&self, message: &SipMessage, rt: &Arc<Runtime>) {
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            State::Early(dialog_users, on_dispose) | State::Confirmed(dialog_users, on_dispose) => {
                for callback in dialog_users {
                    callback.on_terminating_response(message);
                }
                *guard = State::Terminated;
            }
            State::Completed => {
                *guard = State::Terminated;
            }
            _ => {}
        }
    }

    pub fn make_request(
        &self,
        method: &[u8],
        seq: Option<u32>,
    ) -> Result<SipMessage, &'static str> {
        let mut remote_target = (&*self.remote_target.lock().unwrap()).to_vec();

        let guard = self.route_set.lock().unwrap();

        let mut final_route_set = (*guard).clone();

        let mut contains_lr = false;
        let mut new_remote_target = Vec::new();

        if let Some(route) = final_route_set.first() {
            if let Some(addr) = route.as_name_addresses().first() {
                if let Some(uri_part) = &addr.uri_part {
                    // let (_, uri_parameters) = uri_part;

                    for p in uri_part.get_parameter_iterator() {
                        if p.name.eq_ignore_ascii_case(b"lr") {
                            contains_lr = true;

                            let data_size = uri_part.estimated_size();
                            new_remote_target.reserve(data_size);
                            {
                                let mut readers = Vec::new();
                                uri_part.get_readers(&mut readers);
                                match DynamicChain::new(readers).read_to_end(&mut new_remote_target)
                                {
                                    Ok(_) => {}
                                    Err(_) => {} // to-do: early failure
                                }
                            }

                            break;
                        }
                    }

                    // let p = parameter::search(&uri_parameters, b"lr");
                    // if let Some(_) = p {
                    //     if let Some(uri_part_string) = addr.uri_part_to_string() {
                    //         final_route_set = final_route_set.split_off(1);
                    //         let mut r = b"<".to_vec();
                    //         r.extend(remote_target);
                    //         r.extend(b">");
                    //         final_route_set.push(r);

                    //         remote_target = uri_part_string.to_vec();
                    //     }
                    // }
                }
            } else {
                return Err("Abnormal Route-Set");
            }
        }

        if contains_lr {
            final_route_set = final_route_set.split_off(1);
            let mut r = b"<".to_vec();
            r.extend(remote_target);
            r.extend(b">");
            final_route_set.push(r);

            remote_target = new_remote_target;
        }

        if let Some(_) = remote_target.as_standard_uri() {
            let mut message = SipMessage::new_request(method, &remote_target);

            let from_addresses = self.local_uri.as_name_addresses();
            let to_addresses = self.remote_uri.as_name_addresses();

            if from_addresses.len() > 0 && to_addresses.len() > 0 {
                let from = FromTo {
                    addresses: from_addresses,
                    tag: Some(&self.local_tag),
                };

                let from_data_size = from.estimated_size();
                let mut from_data = Vec::with_capacity(from_data_size);
                {
                    let mut readers = Vec::new();
                    from.get_readers(&mut readers);
                    match DynamicChain::new(readers).read_to_end(&mut from_data) {
                        Ok(_) => {}
                        Err(_) => {} // to-do: early failure
                    }
                }

                message.add_header(Header::new(b"From", from_data));

                let to = FromTo {
                    addresses: to_addresses,
                    tag: Some(&self.remote_tag),
                };

                let to_data_size = to.estimated_size();
                let mut to_data = Vec::with_capacity(to_data_size);
                {
                    let mut readers = Vec::new();
                    to.get_readers(&mut readers);
                    match DynamicChain::new(readers).read_to_end(&mut to_data) {
                        Ok(_) => {}
                        Err(_) => {} // to-do: early failure
                    }
                }

                message.add_header(Header::new(b"To", to_data));

                message.add_header(Header::new(b"Call-ID", self.call_id.to_vec()));

                for route in final_route_set {
                    message.add_header(Header::new(b"Route", route));
                }

                let cseq;

                if method == ACK || method == CANCEL {
                    if let Some(seq) = seq {
                        cseq = CSeq { seq, method }
                    } else {
                        return Err("Seq not provided");
                    }
                } else {
                    let seq;
                    let mut guard = self.local_seq.lock().unwrap();
                    match *guard {
                        Some(v) => {
                            seq = v + 1;
                            *guard = Some(seq);
                        }
                        None => {
                            seq = 100;
                            *guard = Some(seq);
                        }
                    }
                    cseq = CSeq { seq, method }
                }

                let cseq_data_size = to.estimated_size();
                let mut cseq_data = Vec::with_capacity(cseq_data_size);
                match cseq.reader().read_to_end(&mut cseq_data) {
                    Ok(_) => {}
                    Err(_) => {} // to-do: early failure
                }

                message.add_header(Header::new(b"CSeq", cseq_data));

                return Ok(message);
            }
        }

        Err("Error building message")
    }

    pub fn cmcc_patch_route_set_on_subscriber_2xx_response(&self, resp_message: &SipMessage) {
        let mut new_route_set = Vec::new();
        if let Some(headers) = resp_message.headers() {
            for record_route_header in HeaderSearch::new(headers, b"Record-Route", true) {
                let route = record_route_header
                    .get_value()
                    .as_header_field()
                    .value
                    .to_vec();
                new_route_set.push(route);
            }
        }
        *self.route_set.lock().unwrap() = new_route_set;
    }
}

pub trait GetDialogHeaders {
    fn get_dialog_headers<'a>(&'a self) -> Option<(&'a Header, HeaderField<'a>, HeaderField<'a>)>;
}

pub trait GetDialogHeaderInfo {
    fn get_dialog_header_info<'a>(&'a self) -> (FromTo<'a>, FromTo<'a>);
}

pub trait GetDialogIdentifier {
    fn get_dialog_identifier<'a>(&'a self) -> Option<SipDialogIdentifier<'a>>;
}

impl GetDialogHeaderInfo for (HeaderField<'_>, HeaderField<'_>) {
    fn get_dialog_header_info<'a>(&'a self) -> (FromTo<'a>, FromTo<'a>) {
        (self.0.as_from_to(), self.1.as_from_to())
    }
}

impl GetDialogIdentifier for (&'_ Header, FromTo<'_>, FromTo<'_>, bool) {
    fn get_dialog_identifier<'a>(&'a self) -> Option<SipDialogIdentifier<'a>> {
        if let (Some(from_tag), Some(to_tag)) = (self.1.tag, self.2.tag) {
            return Some(SipDialogIdentifier {
                call_id: &self.0.get_value(),
                local_tag: if self.3 { from_tag } else { to_tag },
                remote_tag: if self.3 { to_tag } else { from_tag },
            });
        }

        None
    }
}
