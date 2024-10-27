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

pub mod subscribe_request;
pub mod subscriber;
pub mod subscription_identifier;

use std::{
    ops::Add,
    sync::{Arc, Mutex},
};

use tokio::{
    runtime::Runtime,
    sync::mpsc,
    time::{sleep, sleep_until, Duration, Instant},
};

use uuid::Uuid;

use crate::{
    ffi::log::platform_log,
    internet::{header::search, AsHeaderField},
    util::raw_string::{StrEq, ToInt},
};

use self::{
    subscribe_request::SubscribeRequest,
    subscriber::{Subscriber, SubscriberEvent},
    subscription_identifier::{
        get_identifier_from_sip_notify, identifier_equals, SubscriptionIdentifier,
    },
};

use super::{
    sip_core::SipDialogCache, sip_headers::subscription_state::AsSubscriptionState,
    sip_transaction::server_transaction, ClientTransactionCallbacks, ServerTransaction,
    ServerTransactionEvent, SipCore, SipDialog, SipDialogEventCallbacks, SipMessage,
    SipTransactionManager, SipTransport,
};

pub const SERVER_SUPPORT_RFC_6665: bool = false;
pub const TREAT_SUBSCRIBE_487_AS_SUCCESS: bool = true;

pub const LOG_TAG: &str = "sip_subscription";

pub struct Subscription {
    identifier: SubscriptionIdentifier,

    transport: Arc<SipTransport>,

    dialog: Arc<SipDialog>,

    expiration: Arc<Mutex<Instant>>,

    subscriber: Arc<Subscriber>,
}

impl Subscription {
    pub fn new(
        identifier: SubscriptionIdentifier,
        transport: Arc<SipTransport>,
        dialog: &Arc<SipDialog>,
        subscriber: &Arc<Subscriber>,
    ) -> Subscription {
        Subscription {
            identifier,
            transport,
            dialog: Arc::clone(&dialog),
            expiration: Arc::new(Mutex::new(Instant::now())),
            subscriber: Arc::clone(&subscriber),
        }
    }
}

pub fn schedule_refresh(
    subscription_key: &Uuid,
    subscription_dialog_user_key: &Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    subscription: Arc<Subscription>,
    expiration_value: u32,
    scheduled_expiration: Instant,
    scheduled_refresh_point: Instant,
    sm: &Arc<SubscriptionManager>,
    tm: &Arc<SipTransactionManager>,
    rt: &Arc<Runtime>,
) {
    let subscription_key = *subscription_key;
    let subscription_dialog_user_key = Arc::clone(subscription_dialog_user_key);
    {
        let mut guard = subscription.expiration.lock().unwrap();
        if *guard < scheduled_expiration {
            *guard = scheduled_expiration;
        }
    }
    let expiration = Arc::clone(&subscription.expiration);
    let sm = Arc::clone(sm);
    let tm = Arc::clone(tm);
    let transport = Arc::clone(&subscription.transport);
    // let timer_ = Arc::clone(timer);
    let rt_ = Arc::clone(&rt);
    rt.spawn(async move {
        sleep_until(scheduled_refresh_point).await;
        if *expiration.lock().unwrap() == scheduled_expiration {
            send_refresh(
                subscription_key,
                &subscription_dialog_user_key,
                &subscription,
                expiration_value,
                &sm,
                &tm,
                &transport,
                // &timer_,
                &rt_,
            );
        }
    });
}

pub fn send_refresh(
    subscription_key: Uuid,
    subscription_dialog_user_key: &Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    subscription: &Arc<Subscription>,
    expiration: u32,
    sm: &Arc<SubscriptionManager>,
    tm: &Arc<SipTransactionManager>,
    transport: &Arc<SipTransport>,
    rt: &Arc<Runtime>,
) {
    if let Ok(req_message) = subscription
        .subscriber
        .build_request(Some(Arc::clone(&subscription.dialog)), expiration)
    {
        if let Ok(subscribe_request) =
            SubscribeRequest::new(&req_message, Arc::clone(&subscription.subscriber))
        {
            let subscribe_request = Arc::new(subscribe_request);
            let subscribe_request_ = Arc::clone(&subscribe_request);
            sm.register_request(subscribe_request_, rt);
            tm.send_request(
                req_message,
                transport,
                SubscriptionRefreshContext {
                    scheduled_for_disponse: expiration == 0,
                    subscription_key,
                    subscription_dialog_user_key: Arc::clone(subscription_dialog_user_key),
                    subscription: Arc::clone(subscription),
                    subscribe_request,
                    sm: Arc::clone(sm),
                    tm: Arc::clone(tm),
                    rt: Arc::clone(rt),
                },
                rt,
            );
        }
    }
}

pub struct InitialSubscribeContext {
    subscribe_request: Arc<SubscribeRequest>,
    core: Arc<SipCore>,
    rt: Arc<Runtime>,
}

impl InitialSubscribeContext {
    pub fn new(
        subscribe_request: Arc<SubscribeRequest>,
        core: Arc<SipCore>,
        rt: Arc<Runtime>,
    ) -> InitialSubscribeContext {
        InitialSubscribeContext {
            subscribe_request,
            core,
            rt,
        }
    }
}

impl ClientTransactionCallbacks for InitialSubscribeContext {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        let subscriber = self.subscribe_request.get_subscriber();

        if let SipMessage::Response(l, _, _) = &message {
            platform_log(
                LOG_TAG,
                format!(
                    "{} subscribe->on_final_response(): {}",
                    subscriber.name(),
                    l.status_code
                ),
            );

            if l.status_code >= 200 && l.status_code < 300 {
                if !SERVER_SUPPORT_RFC_6665 {
                    let request_headers = self.subscribe_request.get_request_message_headers();

                    let (d_tx, mut d_rx) = tokio::sync::mpsc::channel(1);

                    let ongoing_dialogs = self.core.get_ongoing_dialogs();

                    let ongoing_dialogs_ = Arc::clone(&ongoing_dialogs);

                    self.rt.spawn(async move {
                        if let Some(dialog) = d_rx.recv().await {
                            ongoing_dialogs_.remove_dialog(&dialog);
                        }
                    });

                    if let Ok(dialog) =
                        SipDialog::try_new_as_uac(request_headers, &message, move |d| {
                            match d_tx.blocking_send(d) {
                                Ok(()) => {}
                                Err(e) => {}
                            }
                        })
                    {
                        let mut dialog = Arc::new(dialog);

                        dialog = ongoing_dialogs.add_dialog_if_not_duplicate(&dialog);

                        dialog.cmcc_patch_route_set_on_subscriber_2xx_response(&message);

                        platform_log(LOG_TAG, "dummy dialog created for subscription");
                    }
                }

                if let Some(headers) = message.headers() {
                    if let Some(expires_header) = search(headers, b"Expires", true) {
                        if let Ok(expires) = expires_header
                            .get_value()
                            .as_header_field()
                            .value
                            .to_int::<u32>()
                        {
                            let scheduled_expiration =
                                Instant::now().add(Duration::from_secs(expires as u64));

                            let scheduled_refresh_point = if expires > 300 {
                                Instant::now().add(Duration::from_secs(expires as u64 - 300))
                            } else {
                                Instant::now()
                            };

                            let subscriptions = subscriber.get_subscriptions();

                            let guard = subscriptions.lock().unwrap();

                            for (subscription_key, subscription_dialog_user_key, subscription) in
                                &*guard
                            {
                                schedule_refresh(
                                    subscription_key,
                                    subscription_dialog_user_key,
                                    Arc::clone(subscription),
                                    expires,
                                    scheduled_expiration,
                                    scheduled_refresh_point,
                                    &self.core.get_subscription_manager(),
                                    &self.core.get_transaction_manager(),
                                    // &self.core.get_timer(),
                                    &self.rt,
                                );
                            }
                        }
                    }
                }
            } else {
                if l.status_code == 404
                    || l.status_code == 405
                    || l.status_code == 410
                    || l.status_code == 416
                    || (l.status_code >= 480 && l.status_code <= 485)
                    || l.status_code == 489
                    || l.status_code == 501
                    || l.status_code == 604
                {
                    let subscription_identifier = self.subscribe_request.get_identifier();

                    self.core
                        .get_subscription_manager()
                        .get_registered_request(subscription_identifier, true);

                    // let timer = self.core.get_timer();

                    let subscriptions = subscriber.get_subscriptions();

                    let guard = subscriptions.lock().unwrap();

                    for (_, _, subscription) in &*guard {
                        subscription
                            .dialog
                            .on_terminating_response(&message, &self.rt);
                    }
                }

                if l.status_code == 487 && TREAT_SUBSCRIBE_487_AS_SUCCESS {
                    self.subscribe_request.on_event(); // prevent timer-N from firing
                    subscriber.on_event(SubscriberEvent::SubscribeFailed(200));
                } else {
                    subscriber.on_event(SubscriberEvent::SubscribeFailed(l.status_code as u32));
                }
            }
        }
    }

    fn on_transport_error(&self) {
        let subscriber = self.subscribe_request.get_subscriber();

        subscriber.on_event(SubscriberEvent::SubscribeFailed(0));
    }
}

struct SubscriptionRefreshContext {
    scheduled_for_disponse: bool,
    subscription_key: Uuid,
    subscription_dialog_user_key: Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    subscription: Arc<Subscription>,
    subscribe_request: Arc<SubscribeRequest>,
    sm: Arc<SubscriptionManager>,
    tm: Arc<SipTransactionManager>,
    // timer: Arc<Timer>,
    rt: Arc<Runtime>,
}

impl ClientTransactionCallbacks for SubscriptionRefreshContext {
    fn on_provisional_response(&self, _message: SipMessage) {}

    fn on_final_response(&self, message: SipMessage) {
        if let SipMessage::Response(l, headers, _) = &message {
            platform_log(
                LOG_TAG,
                format!(
                    "refreshing subscribe->on_final_response(): {}",
                    l.status_code
                ),
            );

            if l.status_code >= 200 && l.status_code < 300 {
                if let Some(headers) = headers {
                    if let Some(expires_header) = search(headers, b"Expires", true) {
                        if let Ok(expires) = expires_header
                            .get_value()
                            .as_header_field()
                            .value
                            .to_int::<u32>()
                        {
                            let scheduled_expiration =
                                Instant::now().add(Duration::from_secs(expires as u64));

                            let scheduled_refresh_point = if expires > 300 {
                                Instant::now().add(Duration::from_secs(expires as u64 - 300))
                            } else {
                                Instant::now()
                            };

                            let subscription = Arc::clone(&self.subscription);

                            schedule_refresh(
                                &self.subscription_key,
                                &self.subscription_dialog_user_key,
                                subscription,
                                expires,
                                scheduled_expiration,
                                scheduled_refresh_point,
                                &self.sm,
                                &self.tm,
                                // &self.timer,
                                &self.rt,
                            );
                        }
                    }
                }

                return;
            } else {
                if l.status_code == 404
                    || l.status_code == 405
                    || l.status_code == 410
                    || l.status_code == 416
                    || (l.status_code >= 480 && l.status_code <= 485)
                    || l.status_code == 489
                    || l.status_code == 501
                    || l.status_code == 604
                {
                    if l.status_code == 404
                        || l.status_code == 410
                        || l.status_code == 416
                        || (l.status_code >= 482 && l.status_code <= 485)
                        || l.status_code == 489
                        || l.status_code == 604
                    {
                        self.subscription
                            .dialog
                            .on_terminating_response(&message, &self.rt);
                    } else {
                        self.subscription
                            .dialog
                            .unregister_user(&self.subscription_dialog_user_key);
                    }

                    self.subscribe_request
                        .get_subscriber()
                        .on_event(SubscriberEvent::SubscribeFailed(l.status_code as u32));

                    return;
                }
            }
        }
    }

    fn on_transport_error(&self) {
        self.subscribe_request
            .get_subscriber()
            .remove_subscription(self.subscription_key);
        self.subscription
            .dialog
            .unregister_user(&self.subscription_dialog_user_key);
        self.subscribe_request
            .get_subscriber()
            .on_event(SubscriberEvent::SubscribeFailed(0));
    }
}

pub struct SubscriptionDialogListener {
    subscription: Arc<Subscription>,
    subscription_key: Uuid,
}

impl SubscriptionDialogListener {
    pub fn new(
        subscription: &Arc<Subscription>,
        subscription_key: Uuid,
    ) -> SubscriptionDialogListener {
        SubscriptionDialogListener {
            subscription: Arc::clone(subscription),
            subscription_key,
        }
    }
}

impl SipDialogEventCallbacks for SubscriptionDialogListener {
    fn on_ack(&self, _transaction: &Arc<ServerTransaction>) {}

    fn on_new_request(
        &self,
        transaction: Arc<ServerTransaction>,
        tx: mpsc::Sender<ServerTransactionEvent>,
        // timer: &Timer,
        rt: &Arc<Runtime>,
    ) -> Option<(u16, bool)> {
        let message = transaction.message();

        if let Ok(subscription_identifier) = get_identifier_from_sip_notify(message) {
            if identifier_equals(&self.subscription.identifier, &subscription_identifier) {
                if let Some(headers) = message.headers() {
                    if let Some(subscription_state_header) =
                        search(headers, b"Subscription-State", true)
                    {
                        let subscription_state_header_field =
                            subscription_state_header.get_value().as_header_field();

                        if let Some(subscription_state) =
                            subscription_state_header_field.as_subscription_state()
                        {
                            if subscription_state.state.equals_bytes(b"terminated", false) {
                                if let Some(resp_message) = server_transaction::make_response(
                                    message,
                                    transaction.to_tag(),
                                    200,
                                    b"OK",
                                ) {
                                    server_transaction::send_response(
                                        Arc::clone(&transaction),
                                        resp_message,
                                        tx,
                                        // &timer,
                                        rt,
                                    );
                                }

                                if let Some(content_type_header) =
                                    search(headers, b"Content-Type", true)
                                {
                                    if let Some(body) = message.get_body() {
                                        self.subscription.subscriber.on_event(
                                            SubscriberEvent::ReceivedNotify(
                                                Some(self.subscription_key),
                                                content_type_header.get_value().to_vec(),
                                                body,
                                            ),
                                        );
                                    }
                                }

                                let can_retry = match subscription_state.reason {
                                    Some(b"deactivated") | Some(b"timeout") => true,

                                    Some(b"probation") | Some(b"giveup") => true,

                                    Some(b"noresource") | Some(b"invariant") => false,

                                    _ => true,
                                };

                                self.subscription
                                    .subscriber
                                    .on_event(SubscriberEvent::Terminated(
                                        Some(Arc::clone(&self.subscription.dialog)),
                                        can_retry,
                                        subscription_state.retry_after,
                                    ));

                                // subscriber_remove_terminated_subscription

                                return Some((200, true));
                            } else {
                                if subscription_state.state.equals_bytes(b"pending", false) {
                                    // subscription_update_expire_timer

                                    if let Some(resp_message) = server_transaction::make_response(
                                        message,
                                        transaction.to_tag(),
                                        200,
                                        b"OK",
                                    ) {
                                        server_transaction::send_response(
                                            Arc::clone(&transaction),
                                            resp_message,
                                            tx,
                                            // &timer,
                                            rt,
                                        );
                                    }

                                    return Some((200, false));
                                } else if subscription_state.state.equals_bytes(b"active", false) {
                                    // subscription_update_expire_timer

                                    if let Some(resp_message) = server_transaction::make_response(
                                        message,
                                        transaction.to_tag(),
                                        200,
                                        b"OK",
                                    ) {
                                        server_transaction::send_response(
                                            Arc::clone(&transaction),
                                            resp_message,
                                            tx,
                                            // &timer,
                                            rt,
                                        );
                                    }

                                    if let Some(content_type_header) =
                                        search(headers, b"Content-Type", true)
                                    {
                                        if let Some(body) = message.get_body() {
                                            self.subscription.subscriber.on_event(
                                                SubscriberEvent::ReceivedNotify(
                                                    Some(self.subscription_key),
                                                    content_type_header.get_value().to_vec(),
                                                    body,
                                                ),
                                            );
                                        }
                                    }

                                    return Some((200, false));
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    fn on_terminating_request(&self, message: &SipMessage) {
        todo!()
    }

    fn on_terminating_response(&self, message: &SipMessage) {
        todo!()
    }
}

pub struct SubscriptionManager {
    t1: u64,
    subscribe_requests: Arc<Mutex<Vec<Arc<SubscribeRequest>>>>,
}

impl SubscriptionManager {
    pub fn new(t1: u64) -> SubscriptionManager {
        SubscriptionManager {
            t1,
            subscribe_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn register_request(&self, subscribe_request: Arc<SubscribeRequest>, rt: &Arc<Runtime>) {
        platform_log(
            LOG_TAG,
            format!("register_request {:?}", subscribe_request.get_identifier()),
        );

        let t1 = self.t1;

        let subscribe_request_ = Arc::clone(&subscribe_request);

        self.subscribe_requests
            .lock()
            .unwrap()
            .push(subscribe_request);

        let subscribe_requests = Arc::clone(&self.subscribe_requests);

        rt.spawn(async move {
            sleep(Duration::from_millis(64 * t1)).await;

            let mut guard = subscribe_requests.lock().unwrap();

            let mut i = 0;

            for subscribe_request in &*guard {
                let identifier = subscribe_request.get_identifier();
                let identifier_ = subscribe_request_.get_identifier();
                if identifier_equals(identifier, identifier_) {
                    subscribe_request.on_timer_n();
                    guard.swap_remove(i);
                    break;
                }
                i += 1;
            }
        });
    }

    pub fn get_registered_request(
        &self,
        subscription_identifier: &SubscriptionIdentifier,
        removes: bool,
    ) -> Option<Arc<SubscribeRequest>> {
        let mut guard = self.subscribe_requests.lock().unwrap();
        let mut i = 0;
        for subscribe_request in &*guard {
            let identifier = subscribe_request.get_identifier();
            if identifier_equals(identifier, subscription_identifier) {
                let r = Arc::clone(subscribe_request);
                if removes {
                    guard.swap_remove(i);
                }
                return Some(r);
            }
            i += 1;
        }

        None
    }
}
