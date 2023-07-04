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

use rand::prelude::*;

pub fn create_raw_alpha_numeric_string(length: usize) -> Vec<u8> {
    let mut s = Vec::with_capacity(length);
    let mut rng = rand::thread_rng();
    for _ in 0..length {
        let mut c = rng.gen_range(0..62);
        if c < 10 {
            c = 48 + c
        } else if c < 36 {
            c = 65 + c - 10
        } else {
            c = 97 + c - 36
        }
        s.push(c);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::create_raw_alpha_numeric_string;

    #[test]
    fn test_create_raw_alpha_numeric_string() {
        let data = create_raw_alpha_numeric_string(16);
        let s = String::from_utf8_lossy(&data);

        println!("{}", &s);

        assert_eq!(s.len(), 16)
    }
}
