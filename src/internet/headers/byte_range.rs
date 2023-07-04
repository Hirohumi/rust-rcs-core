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

// slice_representation sr1 = {s->internal + s->start, i1};
// slice_representation sr2 = {s->internal + s->start + i1 + 1, i2};
// slice_representation sr3 = {s->internal + s->start + i2 + 1, s->end - s->start - i2 - 1};

// slice *s1 = slice_copy_representation(sr1);
// slice *s2 = slice_copy_representation(sr2);
// slice *s3 = slice_copy_representation(sr3);

// struct byte_range_header_value *byte_range = calloc(1, sizeof(struct byte_range_header_value));

// byte_range->from = slice_to_integer(s1);
// if (slice_equals_static_str(s2, "*", true))
// {
//     byte_range->to = SIZE_MAX;
// }
// else
// {
//     byte_range->to = slice_to_integer(s2);
// }
// byte_range->total = slice_to_integer(s3);

// return byte_range;
use crate::util::raw_string::ToInt;

pub struct ByteRange {
    pub from: usize,
    pub to: Option<usize>,
    pub total: usize,
}

pub fn parse(s: &[u8]) -> Option<ByteRange> {
    let mut iter = s.iter();
    if let Some(i1) = iter.position(|c| *c == b'-') {
        if let Some(i2) = iter.position(|c| *c == b'/') {
            let s1 = &s[..i1];
            let s2 = &s[i1 + 1..i1 + 1 + i2];
            let s3 = &s[i1 + 1 + i2 + 1..];

            if let Ok(from) = s1.to_int() {
                if let Ok(total) = s3.to_int() {
                    if total >= from || (from == 1 && total == 0) {
                        if s2 == b"*" {
                            return Some(ByteRange {
                                from,
                                to: None,
                                total,
                            });
                        } else if let Ok(to) = s2.to_int() {
                            if total >= to && (to >= from || (from == 1 && to == 0)) {
                                return Some(ByteRange {
                                    from,
                                    to: Some(to),
                                    total,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    None
}
