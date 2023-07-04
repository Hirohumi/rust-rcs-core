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

pub mod msrp_info_reader;
pub mod msrp_info_writer;

pub enum MsrpInterfaceType {
    IPv4,
    IPv6,
}

pub enum MsrpDirection {
    SendOnly,
    ReceiveOnly,
    SendReceive,
}

pub enum MsrpSetupMethod {
    Passive,
    Active,
}

pub struct MsrpInfo<'a> {
    pub protocol: &'a [u8],
    pub address: &'a [u8],
    pub interface_type: MsrpInterfaceType,
    pub port: u16,
    pub path: &'a [u8],
    pub inactive: bool,
    pub direction: MsrpDirection,
    pub setup_method: MsrpSetupMethod,
    pub accept_types: &'a [u8],
    pub accept_wrapped_types: Option<&'a [u8]>,

    pub file_info: Option<MsrpFileInfo<'a>>,
}

pub struct MsrpFileInfo<'a> {
    pub file_selector: &'a [u8],
    pub file_transfer_id: &'a [u8],
    pub file_range: Option<&'a [u8]>,
    pub file_icon: Option<&'a [u8]>,
    pub file_disposition: Option<&'a [u8]>,
}
