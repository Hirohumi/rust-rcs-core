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

extern crate tokio;

use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;

use uuid::Uuid;

use crate::{
    internet::Body,
    sip::{SipDialog, SipDialogEventCallbacks, SipMessage, SipTransactionManager, SipTransport},
    // util::Timer,
};

use super::{send_refresh, Subscription, SubscriptionManager};

pub enum SubscriberEvent {
    ReceivedNotify(Option<Uuid>, Vec<u8>, Arc<Body>), // (subscription_key, content_type, body),
    NearExpiration(Arc<SipDialog>),
    Terminated(Option<Arc<SipDialog>>, bool, u32), // (dialog, can_resubscribe, retry_after),
    SubscribeFailed(u32),                          // status_code
}

pub struct Subscriber {
    name: String, // for logging
    subscriptions: Arc<
        Mutex<
            Vec<(
                Uuid,
                Arc<dyn SipDialogEventCallbacks + Send + Sync>,
                Arc<Subscription>,
            )>,
        >,
    >,
    event_listener: Box<dyn Fn(SubscriberEvent) + Send + Sync>,
    request_builder:
        Box<dyn Fn(Option<Arc<SipDialog>>, u32) -> Result<SipMessage, ()> + Send + Sync>,
}

impl Subscriber {
    pub fn new<EL, RB>(name: &str, event_listener: EL, request_builder: RB) -> Subscriber
    where
        EL: Fn(SubscriberEvent) + Send + Sync + 'static,
        RB: Fn(Option<Arc<SipDialog>>, u32) -> Result<SipMessage, ()> + Send + Sync + 'static,
    {
        Subscriber {
            name: String::from(name),
            subscriptions: Arc::new(Mutex::new(Vec::new())),
            event_listener: Box::new(event_listener),
            request_builder: Box::new(request_builder),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn get_subscriptions(
        &self,
    ) -> &Arc<
        Mutex<
            Vec<(
                Uuid,
                Arc<dyn SipDialogEventCallbacks + Send + Sync>,
                Arc<Subscription>,
            )>,
        >,
    > {
        return &self.subscriptions;
    }

    pub fn attach_subscription(
        &self,
        subscription_key: Uuid,
        subscription_dialog_user_key: Arc<dyn SipDialogEventCallbacks + Send + Sync>,
        subscription: &Arc<Subscription>,
    ) {
        self.subscriptions.lock().unwrap().push((
            subscription_key,
            subscription_dialog_user_key,
            Arc::clone(subscription),
        ));
    }

    pub fn remove_subscription(&self, subscription_key: Uuid) {
        let mut guard = self.subscriptions.lock().unwrap();
        let mut i = 0;
        for (key, _, _) in &*guard {
            if subscription_key == *key {
                guard.swap_remove(i);
                return;
            }
            i += 1;
        }
    }

    pub fn on_event(&self, event: SubscriberEvent) {
        (self.event_listener)(event);
    }

    pub fn stop_subscribing(
        &self,
        sm: &Arc<SubscriptionManager>,
        tm: &Arc<SipTransactionManager>,
        transport: &Arc<SipTransport>,
        rt: &Arc<Runtime>,
    ) {
        let mut guard = self.subscriptions.lock().unwrap();

        for (subscription_key, subscription_dialog_user_key, subscription) in &*guard {
            send_refresh(
                *subscription_key,
                subscription_dialog_user_key,
                subscription,
                0,
                sm,
                tm,
                transport,
                rt,
            );
        }

        guard.clear();
    }

    pub fn extend_all_subscriptions(
        &self,
        expires: u32,
        sm: &Arc<SubscriptionManager>,
        tm: &Arc<SipTransactionManager>,
        transport: &Arc<SipTransport>,
        rt: &Arc<Runtime>,
    ) {
        let guard = self.subscriptions.lock().unwrap();

        for (subscription_key, subscription_dialog_user_key, subscription) in &*guard {
            send_refresh(
                *subscription_key,
                subscription_dialog_user_key,
                subscription,
                expires,
                sm,
                tm,
                transport,
                // timer,
                rt,
            );
        }
    }

    pub fn build_request(
        &self,
        dialog: Option<Arc<SipDialog>>,
        expiration: u32,
    ) -> Result<SipMessage, ()> {
        (self.request_builder)(dialog, expiration)
    }
}
