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

use std::borrow::Cow;

use super::{MsrpDirection, MsrpInfo, MsrpInterfaceType, MsrpSetupMethod};

impl From<MsrpInfo<'_>> for String {
    fn from(msrp_info: MsrpInfo<'_>) -> Self {
        let address_type = match msrp_info.interface_type {
            MsrpInterfaceType::IPv4 => "IP4",
            MsrpInterfaceType::IPv6 => "IP6",
        };

        let address = String::from_utf8_lossy(msrp_info.address);
        let protocol = String::from_utf8_lossy(msrp_info.protocol);

        let path = String::from_utf8_lossy(msrp_info.path);

        let accept_types = String::from_utf8_lossy(msrp_info.accept_types);
        let accept_wrapped_types = match msrp_info.accept_wrapped_types {
            Some(accept_wrapped_types) => String::from_utf8_lossy(accept_wrapped_types),
            None => Cow::Borrowed("*"),
        };

        format!(
            "v=0\n\
        o=+860 0 0 IN {} {}\n\
        s=-\n\
        c=IN {} {}\n\
        t=0 0\n\
        m=message {} {} *\n\
        a={}\n\
        a=path:{}\n\
        {}
        a=setup:{}\n\
        a=connection:new\n\
        a=accept-types:{}\n\
        a=accept-wrapped-types:{}\n",
            address_type,
            address,
            address_type,
            address,
            msrp_info.port,
            protocol,
            match msrp_info.direction {
                MsrpDirection::SendOnly => "sendonly",
                MsrpDirection::ReceiveOnly => "recvonly",
                MsrpDirection::SendReceive => "sendrecv",
            },
            path,
            if msrp_info.inactive {
                "a=inactive\n"
            } else {
                ""
            },
            match msrp_info.setup_method {
                MsrpSetupMethod::Passive => "passive",
                MsrpSetupMethod::Active => "active",
            },
            accept_types,
            accept_wrapped_types
        )
    }
}
