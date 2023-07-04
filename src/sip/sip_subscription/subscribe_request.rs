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

use crate::{
    internet::{header, Header},
    sip::{sip_headers::subscription_state::SubscriptionState, SipMessage},
};

use super::{
    subscriber::{Subscriber, SubscriberEvent},
    subscription_identifier::{get_identifier_from_sip_subscribe, SubscriptionIdentifier},
};

pub struct SubscribeRequest {
    identifier: SubscriptionIdentifier,

    received_notify: Arc<Mutex<bool>>,

    request_message_headers: Vec<Header>,

    subscriber: Arc<Subscriber>,
}

impl SubscribeRequest {
    pub fn new(
        request_message: &SipMessage,
        subscriber: Arc<Subscriber>,
    ) -> Result<SubscribeRequest, ()> {
        if let Ok(identifier) = get_identifier_from_sip_subscribe(request_message) {
            if let Some(headers) = request_message.headers() {
                return Ok(SubscribeRequest {
                    identifier,
                    received_notify: Arc::new(Mutex::new(false)),
                    request_message_headers: headers.to_vec(),
                    subscriber,
                });
            }
        }
        Err(())
    }

    pub fn get_identifier(&self) -> &SubscriptionIdentifier {
        return &self.identifier;
    }

    pub fn on_event(&self) {
        *self.received_notify.lock().unwrap() = true;
    }

    pub fn on_timer_n(&self) {
        if *self.received_notify.lock().unwrap() {
        } else {
            self.subscriber
                .on_event(SubscriberEvent::SubscribeFailed(408));
        }
    }

    pub fn get_request_message_headers(&self) -> &Vec<Header> {
        &self.request_message_headers
    }

    pub fn get_subscriber(&self) -> &Arc<Subscriber> {
        &self.subscriber
    }

    pub fn on_terminating_event(
        &self,
        subscription_state: SubscriptionState,
        message: &SipMessage,
    ) {
        if let Some(headers) = message.headers() {
            if let Some(content_type_header) = header::search(headers, b"Content-Type", true) {
                if let Some(body) = message.get_body() {
                    self.subscriber.on_event(SubscriberEvent::ReceivedNotify(
                        None,
                        content_type_header.get_value().to_vec(),
                        body,
                    ));
                }
            }
        }

        let can_retry = match subscription_state.reason {
            Some(b"deactivated") | Some(b"timeout") => true,

            Some(b"probation") | Some(b"giveup") => true,

            Some(b"noresource") | Some(b"invariant") => false,

            _ => true,
        };

        self.subscriber.on_event(SubscriberEvent::Terminated(
            None,
            can_retry,
            subscription_state.retry_after,
        ));
    }
}
