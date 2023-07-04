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

use super::challenge::Challenge;

pub struct BasicChallengeParams<'a> {
    pub realm: &'a [u8],
}

impl<'a> BasicChallengeParams<'a> {
    pub fn from_challenge(challenge: Challenge<'a>) -> Option<BasicChallengeParams<'a>> {
        for param in challenge.get_params() {
            if param.name == b"realm" {
                if let Some(realm) = param.value {
                    return Some(BasicChallengeParams { realm });
                }
            }
        }

        None
    }
}
