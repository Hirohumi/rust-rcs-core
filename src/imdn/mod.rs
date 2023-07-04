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

use crate::cpim::cpim_message::{CPIMHeaders, CPIMMessage};

use crate::internet::body::message_body::MessageBody;
use crate::internet::header;
use crate::internet::header_field::AsHeaderField;
use crate::internet::headers::content_type::AsContentType;

use crate::util::raw_string::StrEq;

pub struct IMDNInfo<'a> {
    pub imdn_id: &'a [u8],
    pub disposition_notification: Option<&'a [u8]>,
}

pub trait GetIMDNInfo<'a> {
    fn get_imdn_info_from_inflated_headers(
        &'a self,
        headers: Vec<(Vec<u8>, &'a [u8])>,
    ) -> Result<IMDNInfo, &'static str>;
    fn get_imdn_info(&self) -> Result<IMDNInfo, &'static str>;
}

impl<'a> GetIMDNInfo<'a> for CPIMMessage {
    fn get_imdn_info_from_inflated_headers(
        &'a self,
        headers: Vec<(Vec<u8>, &'a [u8])>,
    ) -> Result<IMDNInfo, &'static str> {
        let mut imdn_id: Option<&[u8]> = None;
        let mut disposition_notification: Option<&[u8]> = None;

        for (n, v) in headers {
            if &n == b"<urn:ietf:params:imdn>.Message-ID" {
                imdn_id = Some(v);
            } else if &n == b"<urn:ietf:params:imdn>.Disposition-Notification" {
                disposition_notification = Some(v);
            }
        }

        if let Some(imdn_id) = imdn_id {
            return Ok(IMDNInfo {
                imdn_id,
                disposition_notification,
            });
        }

        Err("cannot find Message-ID")
    }

    fn get_imdn_info(&self) -> Result<IMDNInfo, &'static str> {
        match &self.headers {
            CPIMHeaders::Deflated(headers) => {
                let mut inflated_headers: Vec<(Vec<u8>, &[u8])> = Vec::with_capacity(headers.len());

                let inflator = self.ns.as_inflator();
                for header in headers {
                    inflated_headers.push(inflator(&header));
                }

                self.get_imdn_info_from_inflated_headers(inflated_headers)
            }

            CPIMHeaders::Inflated(headers) => {
                let mut inflated_headers: Vec<(Vec<u8>, &[u8])> = Vec::with_capacity(headers.len());

                for header in headers {
                    inflated_headers.push((header.get_name().to_vec(), header.get_value()));
                }

                self.get_imdn_info_from_inflated_headers(inflated_headers)
            }
        }
    }
}

pub fn message_contains_imdn(message: &MessageBody, notification_checked: bool) -> bool {
    let mut notification_checked = notification_checked;

    if !notification_checked {
        if let Some(content_disposition_header) =
            header::search(&message.headers, b"Content-Disposition", false)
        {
            if content_disposition_header.get_value() == b"notification" {
                notification_checked = true;
            }
        }
    }

    if notification_checked {
        if let Some(content_type_header) = header::search(&message.headers, b"Content-Type", false)
        {
            let content_type_header_field = content_type_header.get_value().as_header_field();
            if let Some(content_type) = content_type_header_field.as_content_type() {
                if content_type.major_type.equals_bytes(b"message", true)
                    && content_type.sub_type.equals_bytes(b"imdn+xml", true)
                {
                    return true;
                }
            }
        }
    }

    false
}
