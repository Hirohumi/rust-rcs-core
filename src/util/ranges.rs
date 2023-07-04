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

use std::ops::Range;

pub trait RangeOperations<Rhs: ?Sized = Self>
where
    Self: Sized,
{
    fn intersects(&self, rhs: &Rhs) -> bool;
    fn covering(&self, rhs: &Rhs) -> bool;
    fn covered_by(&self, rhs: &Rhs) -> bool;
    fn union(&self, rhs: &Rhs) -> Option<Self>;
}

impl<Idx> RangeOperations for Range<Idx>
where
    Idx: PartialOrd + Copy,
{
    fn intersects(&self, rhs: &Range<Idx>) -> bool {
        (self.start < rhs.start && self.end > rhs.start)
            || (rhs.start < self.start && rhs.end > self.start)
    }

    fn covering(&self, rhs: &Range<Idx>) -> bool {
        self.start <= rhs.start && self.end >= rhs.end
    }

    fn covered_by(&self, rhs: &Range<Idx>) -> bool {
        self.start >= rhs.start && self.end <= rhs.end
    }

    fn union(&self, rhs: &Range<Idx>) -> Option<Range<Idx>> {
        if self.start <= rhs.start && self.end >= rhs.start {
            if self.end > rhs.end {
                Some(Range {
                    start: self.start,
                    end: self.end,
                })
            } else {
                Some(Range {
                    start: self.start,
                    end: rhs.end,
                })
            }
        } else if rhs.start <= self.start && rhs.end >= self.start {
            if rhs.end > self.end {
                Some(Range {
                    start: rhs.start,
                    end: rhs.end,
                })
            } else {
                Some(Range {
                    start: rhs.start,
                    end: self.end,
                })
            }
        } else {
            None
        }
    }
}
