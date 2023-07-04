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

use super::{CountryCode, NetworkCode, ThreeDigit};

pub fn impi_from_imsi(imsi: &str, mcc: CountryCode, mnc: NetworkCode) -> String {
    format!(
        "{}@ims.mnc{}.mcc{}.3gppnetwork.org",
        imsi,
        mnc.string_repr(),
        mcc.string_repr()
    )
}

pub fn tmpu_from_impi(impi: &str) -> String {
    format!("sip:{}", impi)
}

pub fn bsf_address(mcc: CountryCode, mnc: NetworkCode) -> String {
    format!(
        "bsf.mnc{}.mcc{}.pub.3gppnetwork.org",
        mnc.string_repr(),
        mcc.string_repr()
    )
}

const BSF_PREFIX: &str = "bsf.";

const SUFFIX: &str = "3gppnetwork.org";

const DOT_SUFFIX: &str = ".3gppnetwork.org";

const PUBLIC_SUFFIX: &str = "pub.3gppnetwork.org";

const DOT_PUBLIC_SUFFIX: &str = ".pub.3gppnetwork.org";

fn make_public_3gpp_domain(domain: &str) -> String {
    if domain != PUBLIC_SUFFIX && !domain.ends_with(DOT_PUBLIC_SUFFIX) {
        let length = domain.len() - SUFFIX.len();

        return format!("{}{}", &domain[..length], PUBLIC_SUFFIX);
    }

    String::from(domain)
}

pub fn bsf_address_from_impi(impi: &str) -> Option<String> {
    if let Some(idx) = impi.find('@') {
        let domain = &impi[idx + 1..];

        if domain == SUFFIX {
            return Some(String::from("bsf.pub.3gppnetwork.org"));
        } else if domain.ends_with(DOT_SUFFIX) {
            let domain = make_public_3gpp_domain(domain);

            if domain.starts_with(BSF_PREFIX) {
                return Some(domain);
            } else {
                return Some(format!("{}{}", BSF_PREFIX, domain));
            }
        } else {
            return Some(format!("{}{}", BSF_PREFIX, domain));
        }
    }

    None
}
