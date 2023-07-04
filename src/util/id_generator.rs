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

use std::sync::atomic::{AtomicU32, Ordering};

pub struct IdGenerator {
    i: AtomicU32,
}

impl IdGenerator {
    pub const fn new() -> IdGenerator {
        IdGenerator {
            i: AtomicU32::new(0),
        }
    }

    pub fn generate(&self) -> u32 {
        return self.i.fetch_add(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {

    static ID_GENERATOR: crate::util::id_generator::IdGenerator =
        crate::util::id_generator::IdGenerator::new();

    #[test]
    fn no_duplicate() {
        let mut threads: std::vec::Vec<std::thread::JoinHandle<()>> =
            std::vec::Vec::with_capacity(10);

        let (tx, rx) = std::sync::mpsc::channel();

        for _ in 0..100 {
            let tx = tx.clone();

            let thread = std::thread::spawn(move || {
                for _ in 0..10000 {
                    let i = ID_GENERATOR.generate();

                    tx.send(i).unwrap();
                }
            });

            threads.push(thread);
        }

        let mut set = std::collections::HashSet::with_capacity(100000);

        for _ in 0..1000000 {
            let i = rx.recv().unwrap();

            assert_eq!(set.insert(i), true);
        }

        for thread in threads {
            thread.join().unwrap();
        }
    }
}
