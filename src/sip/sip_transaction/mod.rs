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

pub mod client_transaction;
pub mod heartbeat_transaction;
pub mod ic_transaction;
pub mod is_transaction;
pub mod nic_transaction;
pub mod nis_transaction;
pub mod server_transaction;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::ffi::log::platform_log;
use crate::internet::Header;
use crate::util::rand;

use self::heartbeat_transaction::HeartbeatTransaction;

use super::sip_message::SipMessage;
use super::sip_message::ACK;
use super::sip_message::CANCEL;
use super::sip_message::INVITE;
use super::sip_message::REGISTER;
use super::sip_transport::{SipTransport, TransportMessage};

use client_transaction::ClientTransaction;
use client_transaction::ClientTransactionCallbacks;
use ic_transaction::ICTransaction;
use is_transaction::ISTransaction;
use nic_transaction::NICTransaction;
use nis_transaction::NISTransaction;
use server_transaction::ServerTransaction;
use server_transaction::ServerTransactionEvent;

const T200_MILLIS: Duration = Duration::from_millis(200);

const T_HEARTBEAT: Duration = Duration::from_secs(10);

pub const T1: Duration = Duration::from_millis(500);
const _T2: Duration = Duration::from_millis(4000);
const _T4: Duration = Duration::from_millis(5000);

const LOG_TAG: &str = "librust_rcs_client";

pub struct SipTransactionManagerEventInterface {
    pub event_rx: mpsc::Receiver<(
        Arc<ServerTransaction>,
        mpsc::Sender<ServerTransactionEvent>,
        mpsc::Receiver<ServerTransactionEvent>,
    )>,
}

pub struct SipTransactionManager {
    transports: Arc<Mutex<Vec<(Arc<SipTransport>, mpsc::Sender<Option<Vec<u8>>>)>>>,
    ctrl_itf: mpsc::Sender<TransportMessage>,
}

impl SipTransactionManager {
    pub fn new(rt: &Arc<Runtime>) -> (SipTransactionManager, SipTransactionManagerEventInterface) {
        let transports: Arc<Mutex<Vec<(Arc<SipTransport>, mpsc::Sender<Option<Vec<u8>>>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let transports_ = Arc::clone(&transports);
        let mut client_transactions: Vec<Arc<ClientTransaction>> = Vec::new();
        let mut server_transactions: Vec<(
            Arc<ServerTransaction>,
            mpsc::Sender<ServerTransactionEvent>,
        )> = Vec::new();
        let mut heartbeat_transactions: Vec<Arc<HeartbeatTransaction>> = Vec::new();
        let (tx, mut rx) = mpsc::channel(8);
        let (ev_tx, ev_rx) = mpsc::channel(8);
        let rt_ = Arc::clone(rt);
        rt.spawn(async move {
            let rt = Arc::clone(&rt_);
            'thread: loop {
                match rx.recv().await { // to-do: use select! to separate TransportMessage or a Kind of Control Message
                    Some(TransportMessage::Incoming(transport, message)) => match &message {
                        SipMessage::Request(req_line, _, _) => {
                            platform_log(LOG_TAG, "incoming sip request");
                            let mut i = 0;
                            while i < server_transactions.len() {
                                let (transaction, tx) = &server_transactions[i];
                                if transaction.is_terminated() {
                                    server_transactions.swap_remove(i);
                                } else if transaction.matches(&message) {
                                    match &**transaction {
                                        ServerTransaction::IS(t) => {
                                            if req_line.method == ACK {
                                                if let Ok(timer_i) = t.on_ack(tx, &rt) {
                                                    if timer_i {
                                                        t.on_timer_i();
                                                    }
                                                }
                                            } else if req_line.method == CANCEL {
                                                if let Ok(timer_h) = t.on_cancel(tx, &rt) {
                                                    if timer_h {
                                                        let t = Arc::clone(&transaction);
                                                        let tx = tx.clone();
                                                        let rt_ = Arc::clone(&rt);
                                                        rt.spawn(async move {
                                                            sleep(64 * T1).await;
                                                            t.on_timer_h(tx, &rt_);
                                                        });
                                                        // thread_timer.schedule(T1 * 64, move || {
                                                        //     t.on_timer_h(&tx);
                                                        // });
                                                    }
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                    continue 'thread;
                                } else {
                                    i = i + 1;
                                }
                            }

                            if req_line.method == INVITE {
                                let transports = Arc::clone(&transports_);
                                let (tx, rx) = mpsc::channel(8);
                                let rt_ = Arc::clone(&rt);
                                let transaction = ISTransaction::new(
                                    message,
                                    &transport,
                                    move |transport_, data| {
                                        let guard = transports.lock().unwrap();
                                        for (transport, tx) in &*guard {
                                            if Arc::ptr_eq(transport, &transport_) { // to-do: usually we would be sending the response message back to where we received the request, but there might be some exceptions though
                                                let tx = tx.clone();
                                                rt_.spawn(async move {
                                                    match tx.send(Some(data)).await {
                                                        Ok(()) => {},
                                                        Err(_) => platform_log(LOG_TAG, "data is not sent to transport"),
                                                    }
                                                });
                                                return true;
                                            }
                                        }
                                        false
                                    },
                                );
                                let transaction = ServerTransaction::IS(transaction);
                                let transaction = Arc::new(transaction);
                                let t = Arc::clone(&transaction);
                                rt.spawn(async move {
                                    sleep(T200_MILLIS).await;
                                    if let ServerTransaction::IS(transaction) = &*t {
                                        transaction.on_timer_100();
                                    }
                                });
                                let t = Arc::clone(&transaction);
                                let tx_ = tx.clone();
                                server_transactions.push((t, tx_));
                                match ev_tx.send((transaction, tx, rx)).await {
                                    Ok(()) => {},
                                    Err(_) => {
                                        platform_log(LOG_TAG, "incoming transaction not send to event processor");
                                    },
                                }
                            } else {
                                let is_cancel = req_line.method == CANCEL;
                                let transports = Arc::clone(&transports_);
                                let (tx, rx) = mpsc::channel(8);
                                let rt_ = Arc::clone(&rt);
                                let transaction = NISTransaction::new(
                                    message,
                                    &transport,
                                    move |transport_, data| {
                                        let guard = transports.lock().unwrap();
                                        for (transport, tx) in &*guard {
                                            if Arc::ptr_eq(transport, &transport_) { // to-do: usually we would be sending the response message back to where we received the request, but there might be some exceptions though
                                                let tx = tx.clone();
                                                rt_.spawn(async move {
                                                    match tx.send(Some(data)).await {
                                                        Ok(()) => {},
                                                        Err(_) => platform_log(LOG_TAG, "data is not sent to transport"),
                                                    }
                                                });
                                                return true;
                                            }
                                        }
                                        false
                                    },
                                );
                                let transaction = ServerTransaction::NIS(transaction);
                                let transaction = Arc::new(transaction);
                                let t = Arc::clone(&transaction);
                                let tx_ = tx.clone();
                                server_transactions.push((t, tx_));
                                if is_cancel {
                                    if let ServerTransaction::NIS(transaction) = &*transaction {
                                        let resp_message = server_transaction::make_response(
                                            &transaction.message,
                                            &transaction.to_tag,
                                            481,
                                            b"Transaction Does Not Exist",
                                        );
                                        if let Some(resp_message) = resp_message {
                                            if let Ok(result) =
                                                transaction.send_response(resp_message)
                                            {
                                                match result {
                                                    nis_transaction::SendResult::TimerJ => {
                                                        transaction.on_timer_j();
                                                        // to-do: udp
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    match ev_tx.send((transaction, tx, rx)).await {
                                        Ok(()) => {},
                                        Err(_) => {
                                            platform_log(LOG_TAG, "incoming transaction not send to event processor");
                                        },
                                    }
                                }
                            }
                        },

                        SipMessage::Response(_, _, _) => {
                            platform_log(LOG_TAG, "incoming sip response");
                            for transaction in &client_transactions {
                                if transaction.matches(&message) {
                                    platform_log(LOG_TAG, "transaction matched");
                                    if let Ok((timer_d, timer_m, timer_k)) =
                                        transaction.on_response(message)
                                    {
                                        platform_log(LOG_TAG, format!("response processed d/{} m/{} k/{}", timer_d, timer_m, timer_k));
                                        if timer_d {
                                            transaction.on_timer_d(); // to-do: udp
                                        }
                                        if timer_m {
                                            let t = Arc::clone(transaction);
                                            rt.spawn(async move {
                                                sleep(64 * T1).await;
                                                t.on_timer_m();
                                            });
                                            // thread_timer.schedule(T1 * 64, move || {
                                            //     t.on_timer_m();
                                            // });
                                        }
                                        if timer_k {
                                            transaction.on_timer_k(); // to-do: udp
                                        }
                                    }
                                    continue 'thread;
                                }
                            }
                        }

                        SipMessage::Ping => {
                            let transport_ = Arc::clone(&transport);
                            let guard = transports_.lock().unwrap();
                            for (transport, tx) in &*guard {
                                if Arc::ptr_eq(transport, &transport_) {
                                    let pong = b"\r\n\r\n".to_vec();
                                    let tx = tx.clone();
                                    rt_.spawn(async move {
                                        match tx.send(Some(pong)).await {
                                            Ok(()) => {},
                                            Err(_) => platform_log(LOG_TAG, "heartbeat response is not sent to transport"),
                                        }
                                    });
                                    break;
                                }
                            }
                        },

                        SipMessage::Pong => {
                            let mut idx = 0;
                            for transaction in &mut heartbeat_transactions {
                                if Arc::ptr_eq(&transaction.transport, &transport) {
                                    transaction.on_response();
                                    heartbeat_transactions.swap_remove(idx);
                                    break;
                                }
                                idx += 1;
                            }
                        },
                    },

                    Some(TransportMessage::Outgoing(transaction)) => {
                        transaction.start();
                        client_transactions.push(transaction);
                    },

                    Some(TransportMessage::Heartbeat(transaction)) => {
                        transaction.start();
                        heartbeat_transactions.push(transaction);
                    },

                    Some(TransportMessage::Drop(transport)) => {
                        let mut i = 0;

                        while i < server_transactions.len() {
                            let (transaction, _) = &server_transactions[i];
                            let transport_ = transaction.transport();
                            if Arc::ptr_eq(transport_, &transport) {
                                let (_, tx) = server_transactions.swap_remove(i);
                                match tx.send(ServerTransactionEvent::TransportError).await {
                                    Ok(()) => {},
                                    Err(_) => platform_log(LOG_TAG, "transaction event not handled"),
                                }
                            } else {
                                i = i + 1;
                            }
                        }

                        i = 0;

                        while i < client_transactions.len() {
                            let transaction = &client_transactions[i];
                            let transport_ = transaction.transport();
                            if Arc::ptr_eq(transport_, &transport) {
                                client_transactions.swap_remove(i).on_transport_error();
                            } else {
                                i = i + 1;
                            }
                        }
                    },

                    Some(TransportMessage::Exit) => {
                        return ();
                    },

                    None => {
                        return ();
                    },
                }
            }
        });

        (
            SipTransactionManager {
                // timer,
                transports,
                ctrl_itf: tx,
                // thread: Some(thread),
            },
            SipTransactionManagerEventInterface { event_rx: ev_rx },
        )
    }

    pub fn send_heartbeat(&self, transport: &Arc<SipTransport>, rt: &Arc<Runtime>) {
        let transport_2 = Arc::clone(transport);
        let tx = self.ctrl_itf.clone();
        let rt_1 = Arc::clone(rt);
        let rt_2 = Arc::clone(rt);
        let transports_1 = Arc::clone(&self.transports);
        let transports_2 = Arc::clone(&self.transports);
        let transaction = HeartbeatTransaction::new(
            transport,
            move |transport_, data| {
                let guard = transports_1.lock().unwrap();
                for (transport, tx) in &*guard {
                    if Arc::ptr_eq(transport, &transport_) {
                        // to-do: usually we would be sending the response message back to where we received the request, but there might be some exceptions though
                        let tx = tx.clone();
                        rt_1.spawn(async move {
                            match tx.send(Some(data)).await {
                                Ok(()) => {}
                                Err(_) => {
                                    platform_log(LOG_TAG, "heartbeat is not sent to transport")
                                }
                            }
                        });
                        return true;
                    }
                }
                false
            },
            move |success| {
                if success {
                    platform_log(LOG_TAG, "heartbeat success");
                } else {
                    platform_log(LOG_TAG, "heartbeat failure, removing transport");
                    let mut guard = transports_2.lock().unwrap();
                    let mut idx = 0;
                    for (transport, _) in &mut *guard {
                        if Arc::ptr_eq(transport, &transport_2) {
                            guard.swap_remove(idx);
                            platform_log(LOG_TAG, "transport dropped");
                            return;
                        }
                        idx += 1;
                    }
                    let t = Arc::clone(&transport_2);
                    let tx = tx.clone();
                    rt_2.spawn(async move {
                        match tx.send(TransportMessage::Drop(t)).await {
                            Ok(()) => {}
                            Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
                        }
                    });
                }
            },
        );

        let transaction = Arc::new(transaction);
        let t = Arc::clone(&transaction);
        rt.spawn(async move {
            sleep(T_HEARTBEAT).await;
            t.on_timeout();
        });

        let tx = self.ctrl_itf.clone();
        rt.spawn(async move {
            match tx.send(TransportMessage::Heartbeat(transaction)).await {
                Ok(()) => {}
                Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
            }
        });
    }

    pub fn send_request<C>(
        &self,
        mut req_message: SipMessage,
        transport: &Arc<SipTransport>,
        callbacks: C,
        rt: &Arc<Runtime>,
    ) where
        C: ClientTransactionCallbacks + Send + Sync + 'static,
    {
        platform_log(
            LOG_TAG,
            format!("calling SipTransactionManager->send_request()"),
        );

        let via = transport.get_via();
        let branch = rand::create_raw_alpha_numeric_string(16);
        let branch = String::from_utf8_lossy(&branch);

        let mut is_register_request = false;

        if let SipMessage::Request(req_line, _, _) = &mut req_message {
            if req_line.method == REGISTER {
                is_register_request = true;
            }
        }

        req_message.add_header_at_front(Header::new(
            b"Via",
            if is_register_request {
                format!("{};branch=z9hG4bK-{};keep", &via, branch)
            } else {
                format!("{};branch=z9hG4bK-{}", &via, branch)
            },
        ));

        req_message.add_header_at_front(Header::new(b"Max-Forwards", b"70"));

        if req_message.get_body().is_none() {
            req_message.add_header(Header::new(b"Content-Length", b"0"));
        }

        // to-do: might need to update Contact header

        let transports = Arc::clone(&self.transports);

        if let SipMessage::Request(req_line, _, _) = &mut req_message {
            if req_line.method == INVITE {
                let rt_ = Arc::clone(rt);
                let transaction = ICTransaction::new(
                    req_message,
                    &transport,
                    move |transport_, data| {
                        let guard = transports.lock().unwrap();
                        for (transport, tx) in &*guard {
                            if Arc::ptr_eq(transport, &transport_) {
                                let tx = tx.clone();
                                rt_.spawn(async move {
                                    match tx.send(Some(data)).await {
                                        Ok(()) => {}
                                        Err(_) => {
                                            platform_log(LOG_TAG, "data is not sent to transport")
                                        }
                                    }
                                });
                                return true;
                            }
                        }
                        false
                    },
                    callbacks,
                );
                let transaction = ClientTransaction::IC(transaction);
                let transaction = Arc::new(transaction);
                let t = Arc::clone(&transaction);
                rt.spawn(async move {
                    sleep(64 * T1).await;
                    t.on_timer_b();
                });
                // self.timer.schedule(T1 * 64, move || {
                //     t.on_timer_b();
                // });
                let tx = self.ctrl_itf.clone();
                rt.spawn(async move {
                    match tx.send(TransportMessage::Outgoing(transaction)).await {
                        Ok(()) => {}
                        Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
                    }
                });
            } else {
                let rt_ = Arc::clone(rt);
                let transaction = NICTransaction::new(
                    req_message,
                    &transport,
                    move |transport_, data| {
                        let guard = transports.lock().unwrap();
                        for (transport, tx) in &*guard {
                            if Arc::ptr_eq(transport, &transport_) {
                                let tx = tx.clone();
                                rt_.spawn(async move {
                                    match tx.send(Some(data)).await {
                                        Ok(()) => {}
                                        Err(_) => {
                                            platform_log(LOG_TAG, "data is not sent to transport")
                                        }
                                    }
                                });
                                return true;
                            }
                        }
                        false
                    },
                    callbacks,
                );
                let transaction: ClientTransaction = ClientTransaction::NIC(transaction);
                let transaction = Arc::new(transaction);
                // timer_e for udp
                let t = Arc::clone(&transaction);
                rt.spawn(async move {
                    sleep(64 * T1).await;
                    t.on_timer_f();
                });
                let tx = self.ctrl_itf.clone();
                rt.spawn(async move {
                    match tx.send(TransportMessage::Outgoing(transaction)).await {
                        Ok(()) => {}
                        Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
                    }
                });
            }
        }
    }

    pub fn get_ctrl_itf(&self) -> mpsc::Sender<TransportMessage> {
        self.ctrl_itf.clone()
    }

    /// # Caution
    ///
    /// Should always register transport first before start reading
    pub fn register_sip_transport(&self, t: Arc<SipTransport>, tx: mpsc::Sender<Option<Vec<u8>>>) {
        self.transports.lock().unwrap().push((t, tx));
    }

    pub fn unregister_sip_transport(&self, t: &Arc<SipTransport>, rt: &Arc<Runtime>) {
        let mut guard = self.transports.lock().unwrap();
        if let Some(position) = &guard.iter().position(|(t_, _)| Arc::ptr_eq(t, t_)) {
            guard.swap_remove(*position);
            platform_log(LOG_TAG, "transport dropped");
        }
        let t = Arc::clone(t);
        let tx = self.ctrl_itf.clone();
        rt.spawn(async move {
            match tx.send(TransportMessage::Drop(t)).await {
                Ok(()) => {}
                Err(_) => platform_log(LOG_TAG, "transaction manager stopped running"),
            }
        });
    }
}
