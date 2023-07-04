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

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

type Callback = Box<dyn FnOnce() + Send + 'static>;

struct TimerSource {
    t: Instant,
    cb: Callback,
}

pub struct Timer {
    cond_pair: Arc<(Mutex<(bool, Vec<TimerSource>, bool)>, Condvar)>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Timer {
    /// Create a new Timer
    ///
    /// timer callbacks are invoked on its inner thread
    pub fn new() -> Timer {
        let v: Vec<TimerSource> = Vec::with_capacity(16);

        let cond_pair = Arc::new((Mutex::new((false, v, false)), Condvar::new()));

        let cloned_pair = Arc::clone(&cond_pair);

        let thread = thread::spawn(move || loop {
            let (mutex, cond) = &*cloned_pair;

            let v = mutex.lock().unwrap();

            let now = Instant::now();

            let mut delay = Duration::MAX;

            for elem in &*v.1 {
                let d = elem.t.saturating_duration_since(now);
                if d < delay {
                    delay = d;
                }
            }

            dbg!(delay);

            let result = cond
                .wait_timeout_while(v, delay, |v| {
                    if v.0 || v.2 {
                        return false;
                    }
                    let now = Instant::now();
                    for elem in &*v.1 {
                        if elem.t < now {
                            return false;
                        }
                    }
                    true
                })
                .unwrap();

            let mut v = result.0;

            v.0 = false;

            let mut i = 0;

            while i < v.1.len() {
                let a = &v.1[i];

                let now = Instant::now();

                if a.t < now {
                    let b = v.1.swap_remove(i);
                    let cb = b.cb;
                    cb();
                } else {
                    i = i + 1;
                }
            }

            if v.2 {
                dbg!("thread exit\n");
                return;
            }
        });

        Timer {
            cond_pair,
            thread: Some(thread),
        }
    }

    /// Schedule a function that will be called once after 'delay'
    ///
    /// execution order of functions scheduled at a a same delay is not guaranteed
    ///
    /// # Warning
    ///
    /// Timer callbacks should be executed as switfly as possible,
    /// if you need to block inside the callback, hand it over to another thread
    ///
    /// # Panics
    ///
    /// The `schedule` function will panic if delay is no bigger than Duration::ZERO.
    pub fn schedule<F>(&self, delay: Duration, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        assert!(delay > Duration::ZERO);

        let (mutex, cond) = &*self.cond_pair;

        let mut v = mutex.lock().unwrap();

        v.0 = true;

        v.1.push(TimerSource {
            t: Instant::now() + delay,
            cb: Box::new(f),
        });

        cond.notify_one();
    }
}

impl Drop for Timer {
    fn drop(&mut self) {
        dbg!("drop\n");

        {
            let (mutex, cond) = &*self.cond_pair;

            let mut v = mutex.lock().unwrap();

            v.2 = true;

            cond.notify_one();
        }

        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn multiple_sources() {
        let timer = super::Timer::new();
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = std::sync::Arc::new(std::sync::Mutex::new(tx));
        for i in 1..6 {
            let tx = std::sync::Arc::clone(&tx);
            print!("schedule {} over timer after {} seconds\n", i, i);
            timer.schedule(super::Duration::from_secs(i), move || {
                print!("send {} to callback\n", i);
                tx.lock().unwrap().send(i).unwrap();
            });
        }

        assert_eq!(Ok(1), rx.recv());
        assert_eq!(Ok(2), rx.recv());
        assert_eq!(Ok(3), rx.recv());
        assert_eq!(Ok(4), rx.recv());
        assert_eq!(Ok(5), rx.recv());

        for i in 1..6 {
            let tx = std::sync::Arc::clone(&tx);
            print!("schedule {} over timer after {} seconds\n", i, 6 - i);
            timer.schedule(super::Duration::from_secs(6 - i), move || {
                print!("send {} to callback\n", i);
                tx.lock().unwrap().send(i).unwrap();
            });
        }

        assert_eq!(Ok(5), rx.recv());
        assert_eq!(Ok(4), rx.recv());
        assert_eq!(Ok(3), rx.recv());
        assert_eq!(Ok(2), rx.recv());
        assert_eq!(Ok(1), rx.recv());

        std::thread::sleep(std::time::Duration::from_secs(8));
    }
}
