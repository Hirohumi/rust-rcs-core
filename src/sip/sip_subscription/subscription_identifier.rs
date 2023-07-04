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

use std::fmt::Debug;

use crate::{
    internet::{header, AsHeaderField},
    util::raw_string::StrEq,
};

use crate::sip::{sip_headers::AsFromTo, SipMessage};

pub struct SubscriptionIdentifier {
    pub call_id: Vec<u8>,
    pub tag: Vec<u8>,
    pub event_type: Vec<u8>,
    pub event_id: Option<Vec<u8>>,
}

impl Clone for SubscriptionIdentifier {
    fn clone(&self) -> Self {
        SubscriptionIdentifier {
            call_id: self.call_id.clone(),
            tag: self.tag.clone(),
            event_type: self.event_type.clone(),
            event_id: self.event_id.clone(),
        }
    }
}

impl Debug for SubscriptionIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let event_id = match &self.event_id {
            Some(event_id) => String::from_utf8_lossy(event_id),
            None => String::from_utf8_lossy(b"None"),
        };

        f.debug_struct("SubscriptionIdentifier")
            .field("call_id", &String::from_utf8_lossy(&self.call_id))
            .field("tag", &String::from_utf8_lossy(&self.tag))
            .field("event_type", &String::from_utf8_lossy(&self.event_type))
            .field("event_id", &event_id)
            .finish()
    }
}

pub fn identifier_equals(lhv: &SubscriptionIdentifier, rhv: &SubscriptionIdentifier) -> bool {
    if lhv.call_id == rhv.call_id && lhv.tag == rhv.tag && lhv.event_type == rhv.event_type {
        match (&lhv.event_id, &rhv.event_id) {
            (Some(l_event_id), Some(r_event_id)) => {
                return l_event_id == r_event_id;
            }

            (None, None) => {
                return true;
            }

            _ => {
                return false;
            }
        }
    }

    false
}

pub fn get_identifier_from_sip_subscribe(
    subscribe_message: &SipMessage,
) -> Result<SubscriptionIdentifier, ()> {
    if let Some(headers) = subscribe_message.headers() {
        if let (Some(call_id_header), Some(from_header), Some(event_header)) = (
            header::search(headers, b"Call-ID", true),
            header::search(headers, b"From", true),
            header::search(headers, b"Event", true),
        ) {
            let from_header_field = from_header.get_value().as_header_field();
            let event_header_field = event_header.get_value().as_header_field();

            let from = from_header_field.as_from_to();

            if let Some(tag) = from.tag {
                return Ok(SubscriptionIdentifier {
                    call_id: call_id_header.get_value().to_vec(),
                    tag: tag.to_vec(),
                    event_type: event_header_field.value.to_vec(),
                    event_id: None,
                });
            }
        }
    }

    Err(())
}

pub fn get_identifier_from_sip_notify(
    notify_message: &SipMessage,
) -> Result<SubscriptionIdentifier, ()> {
    if let Some(headers) = notify_message.headers() {
        if let (Some(call_id_header), Some(to_header), Some(event_header)) = (
            header::search(headers, b"Call-ID", true),
            header::search(headers, b"To", true),
            header::search(headers, b"Event", true),
        ) {
            let to_header_field = to_header.get_value().as_header_field();
            let event_header_field = event_header.get_value().as_header_field();

            let to = to_header_field.as_from_to();

            if let Some(tag) = to.tag {
                let mut event_id: Option<Vec<u8>> = None;

                for parameter in event_header_field.get_parameter_iterator() {
                    if parameter.name.equals_bytes(b"id", true) {
                        if let Some(value) = parameter.value {
                            event_id.replace(value.to_vec());
                        }
                    }
                }

                return Ok(SubscriptionIdentifier {
                    call_id: call_id_header.get_value().to_vec(),
                    tag: tag.to_vec(),
                    event_type: event_header_field.value.to_vec(),
                    event_id,
                });
            }
        }
    }

    Err(())
}
