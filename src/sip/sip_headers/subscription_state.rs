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

use crate::internet::header_field::HeaderField;

use crate::util::raw_string::{StrEq, ToInt};

pub struct SubscriptionState<'a> {
    pub state: &'a [u8],
    pub reason: Option<&'a [u8]>,
    pub retry_after: u32,
    pub expires: u32,
}

impl Debug for SubscriptionState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self.reason {
            Some(reason) => String::from_utf8_lossy(reason),
            None => String::from_utf8_lossy(b"None"),
        };

        f.debug_struct("SubscriptionState")
            .field("state", &String::from_utf8_lossy(self.state))
            .field("reason", &reason)
            .field("retry_after", &self.retry_after)
            .field("expires", &self.expires)
            .finish()
    }
}

pub trait AsSubscriptionState<'a> {
    type Target;
    fn as_subscription_state(&'a self) -> Option<Self::Target>;
}

impl<'a> AsSubscriptionState<'a> for HeaderField<'a> {
    type Target = SubscriptionState<'a>;
    fn as_subscription_state(&'a self) -> Option<SubscriptionState> {
        let mut subscription_state = SubscriptionState {
            state: self.value,
            reason: None,
            retry_after: 0,
            expires: 0,
        };

        if self.value.equals_bytes(b"terminated", false) {
            for parameter in self.get_parameter_iterator() {
                if parameter.name.equals_bytes(b"reason", false) {
                    subscription_state.reason = parameter.value;
                } else if parameter.name.equals_bytes(b"retry-after", false) {
                    if let Some(value) = parameter.value {
                        if let Ok(retry_after) = value.to_int::<u32>() {
                            subscription_state.retry_after = retry_after;
                        }
                    }
                }
            }

            if subscription_state.reason.is_some() {
                return Some(subscription_state);
            }
        } else {
            for parameter in self.get_parameter_iterator() {
                if parameter.name.equals_bytes(b"expires", false) {
                    if let Some(value) = parameter.value {
                        if let Ok(expires) = value.to_int::<u32>() {
                            subscription_state.expires = expires;
                        }
                    }
                }
            }

            return Some(subscription_state);
        }

        None
    }
}
