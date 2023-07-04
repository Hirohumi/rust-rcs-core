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

use std::ops::Add;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::Instant;
use uuid::Uuid;

use crate::ffi::log::platform_log;
use crate::internet::header::{search, Header};
use crate::internet::{header, AsHeaderField};

use crate::sip::sip_dialog::GetDialogHeaderInfo;
use crate::sip::sip_dialog::GetDialogHeaders;
use crate::sip::sip_dialog::GetDialogIdentifier;
use crate::sip::sip_dialog::SipDialog;
use crate::sip::sip_headers::cseq;
use crate::sip::sip_message::SipMessage;
use crate::sip::sip_message::ACK;
use crate::sip::sip_message::BYE;
use crate::sip::sip_message::NOTIFY;
use crate::sip::sip_transaction::server_transaction;
use crate::sip::sip_transaction::server_transaction::ServerTransaction;
use crate::sip::sip_transaction::server_transaction::ServerTransactionEvent;
use crate::sip::sip_transaction::SipTransactionManager;
use crate::sip::sip_transaction::SipTransactionManagerEventInterface;

use crate::util::raw_string::StrEq;

use super::sip_headers::subscription_state::AsSubscriptionState;
use super::sip_subscription::subscriber::SubscriberEvent;
use super::sip_subscription::subscription_identifier::{
    get_identifier_from_sip_notify, SubscriptionIdentifier,
};
use super::sip_subscription::{
    schedule_refresh, Subscription, SubscriptionDialogListener, SubscriptionManager,
    SERVER_SUPPORT_RFC_6665,
};
use super::{SipDialogEventCallbacks, SipTransport};

const LOG_TAG: &str = "sip";

pub struct SipCore {
    subscription_manager: Arc<SubscriptionManager>,
    transaction_manager: Arc<SipTransactionManager>,
    default_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>, // fix-me: SipCore should not be bound to a single identity, the mapping should be managed by client transport
    ongoing_dialogs: Arc<Mutex<Vec<Arc<SipDialog>>>>,
}

impl SipCore {
    pub fn new(
        sm: &Arc<SubscriptionManager>,
        tm: &Arc<SipTransactionManager>,
        mut tm_event_itf: SipTransactionManagerEventInterface,
        allowed_methods: Vec<&'static [u8]>,
        transaction_handlers: Vec<Box<dyn TransactionHandler + Send + Sync>>,
        rt: &Arc<Runtime>,
    ) -> SipCore {
        let default_public_identity: Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>> =
            Arc::new(Mutex::new(None));
        let default_public_identity_ = Arc::clone(&default_public_identity);
        let ongoing_dialogs: Arc<Mutex<Vec<Arc<SipDialog>>>> = Arc::new(Mutex::new(Vec::new()));
        let ongoing_dialogs_ = Arc::clone(&ongoing_dialogs);
        // let timer = Arc::new(Timer::new());
        // let timer_ = Arc::clone(&timer);

        let sm_ = Arc::clone(sm);
        let tm_ = Arc::clone(tm);
        let rt_ = Arc::clone(&rt);

        rt.spawn(async move {
            let default_public_identity = default_public_identity_;
            let ongoing_dialogs = ongoing_dialogs_;
            let allowed_methods = &allowed_methods;
            let transaction_handlers = &transaction_handlers;
            // let timer = timer_;

            'thread: loop {
                let sm = Arc::clone(&sm_);
                let tm = Arc::clone(&tm_);
                let rt = Arc::clone(&rt_);
                if let Some((transaction, tx, rx)) = tm_event_itf.event_rx.recv().await {
                    let message = transaction.message();
                    if let SipMessage::Request(req_line, _, _) = message {
                        if !allowed_methods
                            .iter()
                            .any(|item| *item == &req_line.method[..])
                        {
                            if let Some(mut resp_message) = server_transaction::make_response(
                                message,
                                transaction.to_tag(),
                                405,
                                b"Method Not Allowed",
                            ) {
                                let mut allowed = Vec::new();
                                let mut first = true;
                                for method in allowed_methods {
                                    if first {
                                        first = false;
                                    } else {
                                        allowed.extend(b", ");
                                    }
                                    allowed.extend_from_slice(method);
                                }

                                resp_message.add_header(Header::new(b"Allow", allowed));

                                server_transaction::send_response(
                                    transaction,
                                    resp_message,
                                    tx,
                                    // &timer,
                                    &rt,
                                );
                            }

                            continue 'thread;
                        }

                        if let Some((call_id, from, to)) = message.get_dialog_headers() {
                            let from_to = (from, to);
                            let (from, to) = from_to.get_dialog_header_info();
                            if let Some(lh_dialog_identifier) =
                                (call_id, from, to, false).get_dialog_identifier()
                            {
                                if !SERVER_SUPPORT_RFC_6665 {
                                    if req_line.method == NOTIFY {
                                        process_out_of_dialog_server_transaction(
                                            sm,
                                            tm,
                                            transaction_handlers,
                                            transaction,
                                            &default_public_identity,
                                            &ongoing_dialogs,
                                            tx,
                                            rx,
                                            // &timer,
                                            &rt,
                                        );

                                        continue 'thread;
                                    }
                                }

                                let guard = ongoing_dialogs.lock().unwrap();
                                for dialog in &*guard {
                                    let rh_dialog_identifier = dialog.dialog_identifier();
                                    if lh_dialog_identifier == rh_dialog_identifier {
                                        if req_line.method == ACK {
                                            dialog.on_ack(&transaction);
                                            continue 'thread;
                                        }

                                        let lh_seq = cseq::get_message_seq(message);

                                        match lh_seq {
                                            Ok(lh_seq) => {
                                                let seq = dialog.remote_seq();

                                                let mut seq_guard = seq.lock().unwrap();

                                                if let Some(rh_seq) = *seq_guard {
                                                    if rh_seq >= lh_seq {
                                                        if let Some(resp_message) =
                                                            server_transaction::make_response(
                                                                message,
                                                                transaction.to_tag(),
                                                                500,
                                                                b"Server Internal Error",
                                                            )
                                                        {
                                                            server_transaction::send_response(
                                                                transaction,
                                                                resp_message,
                                                                tx,
                                                                // &timer,
                                                                &rt,
                                                            );
                                                        }

                                                        continue 'thread;
                                                    }
                                                }

                                                if req_line.method == BYE {
                                                    dialog.on_terminating_request(message, &rt);

                                                    if let Some(resp_message) =
                                                        server_transaction::make_response(
                                                            message,
                                                            transaction.to_tag(),
                                                            200,
                                                            b"OK",
                                                        )
                                                    {
                                                        server_transaction::send_response(
                                                            transaction,
                                                            resp_message,
                                                            tx,
                                                            // &timer,
                                                            &rt,
                                                        );
                                                    }

                                                    continue 'thread;
                                                }

                                                // 	if !subscription.SERVER_SUPPORT_RFC_6665 {

                                                // 		if r.Method == "NOTIFY" {

                                                // 			// since we created dialog on 200 OK response, we need to add usages here

                                                // 			sm := subscription.GetSubscriptionManager()

                                                // 			sm.CheckSubscriptionMissing(message, d, func(missing bool, s *subscription.Subscription) {

                                                // 				if missing {

                                                // 					u := &dialog.DialogUser{
                                                // 						D:   d,
                                                // 						Itf: s,
                                                // 					}

                                                // 					d.AddUser(u)

                                                // 					s.SetDialogUser(u)
                                                // 				}

                                                // 				d.ProcessMidDialogRequest(st)
                                                // 			})

                                                // 			return
                                                // 		}
                                                // 	}

                                                dialog.on_request(
                                                    &transaction,
                                                    tx,
                                                    &rt,
                                                    &mut seq_guard,
                                                    lh_seq,
                                                );

                                                continue 'thread;
                                            }

                                            Err(_) => {
                                                if let Some(resp_message) =
                                                    server_transaction::make_response(
                                                        message,
                                                        transaction.to_tag(),
                                                        400,
                                                        b"Bad Request",
                                                    )
                                                {
                                                    server_transaction::send_response(
                                                        transaction,
                                                        resp_message,
                                                        tx,
                                                        // &timer,
                                                        &rt,
                                                    );
                                                }

                                                continue 'thread;
                                            }
                                        }
                                    }
                                }

                                if let Some(resp_message) = server_transaction::make_response(
                                    message,
                                    transaction.to_tag(),
                                    481,
                                    b"Call Does Not Exist",
                                ) {
                                    server_transaction::send_response(
                                        transaction,
                                        resp_message,
                                        tx,
                                        // &timer
                                        &rt,
                                    );
                                }

                                continue 'thread;
                            }
                        }

                        process_out_of_dialog_server_transaction(
                            sm,
                            tm,
                            transaction_handlers,
                            transaction,
                            &default_public_identity,
                            &ongoing_dialogs,
                            tx,
                            rx,
                            // &timer,
                            &rt,
                        );
                    } else {
                        panic! {"impossible condition"};
                    }
                } else {
                    return ();
                }
            }
        });

        SipCore {
            subscription_manager: Arc::clone(sm),
            transaction_manager: Arc::clone(tm),
            default_public_identity,
            ongoing_dialogs,
            // timer,
        }
    }

    pub fn get_subscription_manager(&self) -> Arc<SubscriptionManager> {
        Arc::clone(&self.subscription_manager)
    }

    pub fn get_transaction_manager(&self) -> Arc<SipTransactionManager> {
        Arc::clone(&self.transaction_manager)
    }

    pub fn set_default_public_identity(
        &self,
        default_public_identity: String,
        sip_instance_id: String,
        transport: Arc<SipTransport>,
    ) {
        (*self.default_public_identity.lock().unwrap()).replace((
            transport,
            default_public_identity,
            sip_instance_id,
        ));
    }

    pub fn get_default_public_identity(&self) -> Option<(Arc<SipTransport>, String, String)> {
        self.default_public_identity.lock().unwrap().clone()
    }

    pub fn get_ongoing_dialogs(&self) -> Arc<Mutex<Vec<Arc<SipDialog>>>> {
        Arc::clone(&self.ongoing_dialogs)
    }

    // pub fn get_timer(&self) -> Arc<Timer> {
    //     Arc::clone(&self.timer)
    // }
}

pub trait SipDialogCache {
    fn add_dialog(&self, dialog: &Arc<SipDialog>);
    fn add_dialog_if_not_duplicate(&self, dialog: &Arc<SipDialog>) -> Arc<SipDialog>;
    fn remove_dialog(&self, dialog: &Arc<SipDialog>);
}

impl SipDialogCache for Arc<Mutex<Vec<Arc<SipDialog>>>> {
    fn add_dialog(&self, dialog: &Arc<SipDialog>) {
        self.lock().unwrap().push(Arc::clone(dialog));
    }

    fn add_dialog_if_not_duplicate(&self, dialog: &Arc<SipDialog>) -> Arc<SipDialog> {
        let mut guard = self.lock().unwrap();
        for d in &*guard {
            if d.dialog_identifier() == dialog.dialog_identifier() {
                return Arc::clone(d);
            }
        }
        guard.push(Arc::clone(dialog));
        Arc::clone(dialog)
    }

    fn remove_dialog(&self, dialog: &Arc<SipDialog>) {
        let mut guard = self.lock().unwrap();
        if let Some(idx) = guard.iter().position(|d| Arc::ptr_eq(d, dialog)) {
            guard.swap_remove(idx);
        }
    }
}

fn process_out_of_dialog_notify_request(
    sm: Arc<SubscriptionManager>,
    tm: Arc<SipTransactionManager>,
    subscription_identifier: &SubscriptionIdentifier,
    transaction: Arc<ServerTransaction>,
    default_public_identity: &Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,
    ongoing_dialogs: &Arc<Mutex<Vec<Arc<SipDialog>>>>,
    tx: mpsc::Sender<ServerTransactionEvent>,
    rx: mpsc::Receiver<ServerTransactionEvent>,
    rt: &Arc<Runtime>,
) {
    platform_log(LOG_TAG, "calling process_out_of_dialog_notify_request()");

    let mut subscribe_request_can_fork = true;

    if subscription_identifier
        .event_type
        .equals_bytes(b"reg", false)
    {
        subscribe_request_can_fork = false;
    }

    let message = transaction.message();

    if let Some(headers) = message.headers() {
        if let Some(subscription_state_header) = search(headers, b"Subscription-State", true) {
            let subscription_state_header_field =
                subscription_state_header.get_value().as_header_field();
            if let Some(subscription_state) =
                subscription_state_header_field.as_subscription_state()
            {
                platform_log(
                    LOG_TAG,
                    format!("with subscription state of {:?}", subscription_state),
                );

                if let Some(subscribe_request) =
                    sm.get_registered_request(&subscription_identifier, !subscribe_request_can_fork)
                {
                    platform_log(LOG_TAG, "found corresponding subscribe request");
                    subscribe_request.on_event();
                    if subscription_state.state.equals_bytes(b"terminated", false) {
                        platform_log(LOG_TAG, "process terminated subscription state");
                        subscribe_request.on_terminating_event(subscription_state, message);
                    } else {
                        if let Some(mut resp_message) = server_transaction::make_response(
                            message,
                            transaction.to_tag(),
                            200,
                            b"OK",
                        ) {
                            let guard = default_public_identity.lock().unwrap();

                            if let Some((transport, contact_identity, instance_id)) = &*guard {
                                let transport_ = transaction.transport();
                                if Arc::ptr_eq(transport, transport_) {
                                    resp_message.add_header(Header::new(
                                        b"Contact",
                                        format!(
                                            "<{}>;+sip.instance=\"{}\"",
                                            contact_identity, instance_id
                                        ), // to-do: is transport_address neccessary? also check reg-flow SUBSCRIBE
                                    ));
                                }
                            }

                            let (d_tx, mut d_rx) = tokio::sync::mpsc::channel(1);

                            let ongoing_dialogs_ = Arc::clone(&ongoing_dialogs);

                            rt.spawn(async move {
                                if let Some(dialog) = d_rx.recv().await {
                                    ongoing_dialogs_.remove_dialog(&dialog);
                                }
                            });

                            if let Ok(dialog) =
                                SipDialog::try_new_as_uas(message, &resp_message, move |d| {
                                    match d_tx.blocking_send(d) {
                                        Ok(()) => {}
                                        Err(e) => {}
                                    }
                                })
                            {
                                let mut dialog = Arc::new(dialog);

                                if SERVER_SUPPORT_RFC_6665 {
                                    ongoing_dialogs.add_dialog(&dialog);
                                } else {
                                    dialog = ongoing_dialogs.add_dialog_if_not_duplicate(&dialog);
                                }

                                server_transaction::send_response(
                                    Arc::clone(&transaction),
                                    resp_message,
                                    tx,
                                    // timer,
                                    rt,
                                );

                                let subscriber = subscribe_request.get_subscriber();

                                let identifier = subscription_identifier.clone();

                                let transport = transaction.transport();

                                let subscription = Subscription::new(
                                    identifier,
                                    Arc::clone(transport),
                                    &dialog,
                                    subscriber,
                                );

                                let subscription = Arc::new(subscription);

                                let subscription_key = Uuid::new_v4();

                                let dialog_user_key: Arc<
                                    dyn SipDialogEventCallbacks + Send + Sync,
                                > = dialog.register_user(SubscriptionDialogListener::new(
                                    &subscription,
                                    subscription_key,
                                ));

                                let dialog_user_key_ = Arc::clone(&dialog_user_key);
                                if subscription_state.state.equals_bytes(b"pending", false) {
                                    platform_log(LOG_TAG, "process pending subscription state");
                                    subscriber.attach_subscription(
                                        subscription_key,
                                        dialog_user_key_,
                                        &subscription,
                                    );

                                    let expiration_value = subscription_state.expires;

                                    let scheduled_expiration = Instant::now().add(
                                        Duration::from_secs(subscription_state.expires as u64),
                                    );

                                    let scheduled_refresh_point =
                                        if subscription_state.expires > 300 {
                                            Instant::now().add(Duration::from_secs(
                                                subscription_state.expires as u64 - 300,
                                            ))
                                        } else {
                                            Instant::now()
                                        };

                                    schedule_refresh(
                                        &subscription_key,
                                        &dialog_user_key,
                                        subscription,
                                        expiration_value,
                                        scheduled_expiration,
                                        scheduled_refresh_point,
                                        &sm,
                                        &tm,
                                        // timer,
                                        rt,
                                    )
                                } else if subscription_state.state.equals_bytes(b"active", false) {
                                    platform_log(LOG_TAG, "process active subscription state");

                                    subscriber.attach_subscription(
                                        subscription_key,
                                        dialog_user_key,
                                        &subscription,
                                    );

                                    // subscription_update_expire_timer(s, subscription_state->expires);

                                    if let Some(headers) = message.headers() {
                                        if let Some(content_type_header) =
                                            header::search(headers, b"Content-Type", true)
                                        {
                                            platform_log(LOG_TAG, "got Content-Type header");
                                            if let Some(body) = message.get_body() {
                                                platform_log(LOG_TAG, "got message body");
                                                subscriber.on_event(
                                                    SubscriberEvent::ReceivedNotify(
                                                        Some(subscription_key),
                                                        content_type_header.get_value().to_vec(),
                                                        body,
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                }
                            } else {
                                platform_log(LOG_TAG, "error creating dialog");

                                server_transaction::send_response(
                                    transaction,
                                    resp_message,
                                    tx,
                                    // timer,
                                    rt,
                                );
                            }
                        }
                    }
                } else {
                    platform_log(LOG_TAG, "missing corresponding subscribe request");
                    if let Some(resp_message) = server_transaction::make_response(
                        message,
                        transaction.to_tag(),
                        481,
                        b"Call Does Not Exist",
                    ) {
                        server_transaction::send_response(transaction, resp_message, tx, rt);
                    }
                }

                return;
            }
        }

        if let Some(resp_message) =
            server_transaction::make_response(message, transaction.to_tag(), 400, b"Bad Request")
        {
            server_transaction::send_response(
                transaction,
                resp_message,
                tx,
                // timer,
                rt,
            );
        }
    }
}

fn process_out_of_dialog_server_transaction(
    sm: Arc<SubscriptionManager>,
    tm: Arc<SipTransactionManager>,
    transaction_handlers: &Vec<Box<dyn TransactionHandler + Send + Sync>>,
    transaction: Arc<ServerTransaction>,
    default_public_identity: &Arc<Mutex<Option<(Arc<SipTransport>, String, String)>>>,
    ongoing_dialogs: &Arc<Mutex<Vec<Arc<SipDialog>>>>,
    tx: mpsc::Sender<ServerTransactionEvent>,
    rx: mpsc::Receiver<ServerTransactionEvent>,
    // timer: &Arc<Timer>,
    rt: &Arc<Runtime>,
) {
    platform_log(
        LOG_TAG,
        "calling process_out_of_dialog_server_transaction()",
    );

    let message = transaction.message();

    if let SipMessage::Request(req_line, _, _) = message {
        if req_line.method == ACK || req_line.method == BYE {
            if let Some(resp_message) = server_transaction::make_response(
                message,
                transaction.to_tag(),
                481,
                b"Call Does Not Exist",
            ) {
                server_transaction::send_response(transaction, resp_message, tx, rt);
            }

            return;
        }

        if req_line.method == NOTIFY {
            if let Ok(subscription_identifier) = get_identifier_from_sip_notify(message) {
                platform_log(
                    LOG_TAG,
                    format!(
                        "receiving NOTIFY with identifier {:?}",
                        &subscription_identifier
                    ),
                );

                process_out_of_dialog_notify_request(
                    sm,
                    tm,
                    &subscription_identifier,
                    transaction,
                    default_public_identity,
                    ongoing_dialogs,
                    tx,
                    rx,
                    // timer,
                    rt,
                );
                return;
            }

            if let Some(resp_message) = server_transaction::make_response(
                message,
                transaction.to_tag(),
                400,
                b"Bad Request",
            ) {
                server_transaction::send_response(transaction, resp_message, tx, rt);
            }
            return;
        }

        let mut channels = Some((tx, rx));

        for handler in transaction_handlers {
            if handler.handle_transaction(
                &transaction,
                ongoing_dialogs,
                &mut channels,
                //  timer,
                rt,
            ) {
                platform_log(
                    LOG_TAG,
                    "out of dialog server transaction successfully handled",
                );

                return;
            }
        }

        if let Some((tx, _)) = channels {
            if let Some(resp_message) = server_transaction::make_response(
                message,
                transaction.to_tag(),
                500,
                b"Server Internal Error",
            ) {
                server_transaction::send_response(
                    transaction,
                    resp_message,
                    tx,
                    // timer,
                    rt,
                );
            }
        }
    }
}

pub trait TransactionHandler {
    fn handle_transaction(
        &self,
        transaction: &Arc<ServerTransaction>,
        ongoing_dialogs: &Arc<Mutex<Vec<Arc<SipDialog>>>>,
        channels: &mut Option<(
            mpsc::Sender<ServerTransactionEvent>,
            mpsc::Receiver<ServerTransactionEvent>,
        )>,
        // timer: &Timer,
        rt: &Arc<Runtime>,
    ) -> bool;
}
