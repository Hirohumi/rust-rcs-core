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

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::internet::header;
use crate::internet::header_field::AsHeaderField;
use crate::internet::headers::supported::Supported;

use crate::sip::sip_dialog::SipDialog;
use crate::sip::sip_dialog::SipDialogEventCallbacks;
use crate::sip::sip_headers::session_expires::AsSessionExpires;
use crate::sip::sip_message::SipMessage;
use crate::sip::sip_transaction::server_transaction::ServerTransaction;

use crate::util::raw_string::ToInt;
// use crate::util::timer::Timer;

pub enum SipSessionEvent {
    HangupBeforeConfirmingDialog(Arc<SipDialog>),
    Started,
    ShouldRefresh(Arc<SipDialog>), // to-do: provide a callback so we can re-try UPDATE if failed with a non-dialog-terminating error
    Expired(Arc<SipDialog>),
}

pub trait SipSessionEventCallback {
    fn on_event(&self, ev: SipSessionEvent);
}

pub struct SipSessionEventReceiver {
    pub tx: mpsc::Sender<SipSessionEvent>,
    pub rt: Arc<Runtime>,
}

impl SipSessionEventCallback for SipSessionEventReceiver {
    fn on_event(&self, ev: SipSessionEvent) {
        let tx = self.tx.clone();
        self.rt.spawn(async move {
            match tx.send(ev).await {
                Ok(()) => {}
                Err(e) => {}
            }
        });
    }
}

pub struct EarlySession {
    dialogs: Vec<(
        Arc<SipDialog>,
        Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    )>,
}

pub struct ConfirmedSession {
    dialog: (
        Arc<SipDialog>,
        Arc<dyn SipDialogEventCallbacks + Send + Sync>,
    ),
    timeout_counter: Arc<Mutex<Option<SessionTimeoutCounter>>>,
}

pub enum SipSessionState {
    Early(EarlySession),
    Confirmed(ConfirmedSession),
    HungUp,
}

pub struct SipSession<T> {
    inner: Arc<T>,
    state: Arc<Mutex<SipSessionState>>,
    callback: Arc<Box<dyn SipSessionEventCallback + Send + Sync>>,
}

impl<T> SipSession<T> {
    pub fn new<C>(inner: &Arc<T>, callback: C) -> SipSession<T>
    where
        C: SipSessionEventCallback + Send + Sync + 'static,
    {
        SipSession {
            inner: Arc::clone(inner),
            state: Arc::new(Mutex::new(SipSessionState::Early(EarlySession {
                dialogs: Vec::new(),
            }))),
            callback: Arc::new(Box::new(callback)),
        }
    }

    pub fn get_inner(&self) -> Arc<T> {
        Arc::clone(&self.inner)
    }

    pub fn setup_early_dialog<C>(&self, dialog: &Arc<SipDialog>, callback: C)
    where
        C: SipDialogEventCallbacks + Send + Sync + 'static,
    {
        let mut guard = self.state.lock().unwrap();
        match &mut *guard {
            SipSessionState::Early(early) => {
                let callback = dialog.register_user(callback);
                early.dialogs.push((Arc::clone(dialog), callback));
            }
            _ => {}
        }
    }

    pub fn setup_confirmed_dialog<C>(&self, dialog: &Arc<SipDialog>, callback: C)
    where
        C: SipDialogEventCallbacks + Send + Sync + 'static,
    {
        let mut guard = self.state.lock().unwrap();
        match *guard {
            SipSessionState::Early(_) => {
                let callback = dialog.register_user(callback);
                *guard = SipSessionState::Confirmed(ConfirmedSession {
                    dialog: (Arc::clone(dialog), callback),
                    timeout_counter: Arc::new(Mutex::new(None)),
                });
                self.callback.on_event(SipSessionEvent::Started);
            }
            _ => {}
        }
    }

    pub fn mark_session_active(&self) {
        let guard = self.state.lock().unwrap();
        match &*guard {
            SipSessionState::Confirmed(confirmed) => {
                let mut guard = confirmed.timeout_counter.lock().unwrap();
                match &mut *guard {
                    Some(counter) => {
                        counter.mark_active();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    pub fn schedule_refresh(
        &self,
        timeout: u32,
        is_refresher: bool,
        rt: &Arc<Runtime>, /* timer: &Timer */
    ) {
        let guard = self.state.lock().unwrap();
        match &*guard {
            SipSessionState::Confirmed(confirmed) => {
                let duration = Duration::from_secs(timeout.into());
                let mut guard = confirmed.timeout_counter.lock().unwrap();
                match &mut *guard {
                    Some(counter) => {
                        let timer_counter = Arc::clone(&confirmed.timeout_counter);
                        if let Some(expiration) = counter.mark_expiration(duration, is_refresher) {
                            let (dialog, _) = &confirmed.dialog;
                            schedule(
                                timer_counter,
                                expiration,
                                duration,
                                // timer,
                                dialog,
                                rt,
                                &self.callback,
                            );
                        }
                    }
                    None => {
                        let expiration = Instant::now() + duration;
                        *guard = Some(SessionTimeoutCounter::new(expiration, is_refresher));
                        let timer_counter = Arc::clone(&confirmed.timeout_counter);
                        let (dialog, _) = &confirmed.dialog;
                        schedule(
                            timer_counter,
                            expiration,
                            duration,
                            // timer,
                            dialog,
                            rt,
                            &self.callback,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    pub fn hang_up(&self) {
        let mut guard = self.state.lock().unwrap();
        match &*guard {
            SipSessionState::Early(early) => {
                for (dialog, callback) in &early.dialogs {
                    // let completed = dialog.unregister_user(*id);
                    // if completed {
                    //     dialog.call_last_user_removed_callback(Arc::clone(dialog));
                    // }
                    if let Some(on_dispose) = dialog.unregister_user(callback) {
                        // to-do: make sure dialog is actually in Early State
                        let dialog = Arc::clone(dialog);
                        on_dispose(dialog);
                    }
                    let dialog = Arc::clone(dialog);
                    self.callback
                        .on_event(SipSessionEvent::HangupBeforeConfirmingDialog(dialog));
                }
                *guard = SipSessionState::HungUp;
            }
            SipSessionState::Confirmed(confirmed) => {
                let (dialog, callback) = &confirmed.dialog;
                // let completed = dialog.unregister_user(*id);
                // if completed {
                //     dialog.call_last_user_removed_callback(Arc::clone(dialog));
                // }
                if let Some(on_dispose) = dialog.unregister_user(callback) {
                    let dialog = Arc::clone(dialog);
                    on_dispose(dialog);
                }
                *guard = SipSessionState::HungUp;
            }
            _ => {}
        }
    }
}

pub enum Refresher {
    UAC,
    UAS,
}

pub struct SessionTimeoutCounter {
    active_until: Instant,
    expiration: Instant,
    is_refresher: bool,
}

impl SessionTimeoutCounter {
    pub fn new(expiration: Instant, is_refresher: bool) -> SessionTimeoutCounter {
        SessionTimeoutCounter {
            active_until: Instant::now(),
            expiration,
            is_refresher,
        }
    }

    pub fn mark_active(&mut self) {
        self.active_until = Instant::now();
    }

    pub fn expiration(&self) -> Instant {
        self.expiration
    }

    pub fn mark_expiration(&mut self, duration: Duration, is_refresher: bool) -> Option<Instant> {
        let expiration = Instant::now() + duration;
        self.is_refresher = is_refresher;
        if self.expiration < expiration {
            self.expiration = expiration;
            return Some(expiration);
        }
        None
    }

    pub fn on_refresh_timer(
        &self,
        dialog: Arc<SipDialog>,
        callback: Arc<Box<dyn SipSessionEventCallback + Send + Sync>>,
    ) {
        let idle_time = Instant::now() - self.active_until;
        if idle_time < Duration::from_secs(3600) {
            if self.is_refresher {
                callback.on_event(SipSessionEvent::ShouldRefresh(dialog));
            }
        }
    }

    pub fn on_expire_timer(
        &self,
        dialog: Arc<SipDialog>,
        callback: Arc<Box<dyn SipSessionEventCallback + Send + Sync>>,
    ) {
        if Instant::now() > self.expiration {
            callback.on_event(SipSessionEvent::Expired(dialog));
        }
    }
}

fn schedule(
    timer_counter: Arc<Mutex<Option<SessionTimeoutCounter>>>,
    expiration: Instant,
    duration: Duration,
    // timer: &Timer,
    dialog: &Arc<SipDialog>,
    rt: &Arc<Runtime>,
    callback: &Arc<Box<dyn SipSessionEventCallback + Send + Sync>>,
) {
    let duration_refresh = duration - Duration::from_secs(120); // to-do: lower limit
    let timer_counter_ = Arc::clone(&timer_counter);
    let dialog_ = Arc::clone(dialog);
    let callback_ = Arc::clone(callback);
    // timer.schedule(duration_refresh, move || {
    //     let timer_counter = timer_counter_;
    //     let mut guard = timer_counter.lock().unwrap();
    //     match &mut *guard {
    //         Some(timer_counter) => {
    //             timer_counter.on_refresh_timer(dialog_, callback_);
    //         }
    //         None => {}
    //     }
    // });
    rt.spawn(async move {
        sleep(duration_refresh).await;
        let timer_counter = timer_counter_;
        let mut guard = timer_counter.lock().unwrap();
        match &mut *guard {
            Some(timer_counter) => {
                timer_counter.on_refresh_timer(dialog_, callback_);
            }
            None => {}
        }
    });

    let dialog_ = Arc::clone(dialog);
    let callback_ = Arc::clone(callback);
    // timer.schedule(duration, move || {
    //     let mut guard = timer_counter.lock().unwrap();
    //     match &mut *guard {
    //         Some(timer_counter) => {
    //             if expiration == timer_counter.expiration() {
    //                 timer_counter.on_expire_timer(dialog_, callback_);
    //             }
    //         }
    //         None => {}
    //     }
    // });
    rt.spawn(async move {
        sleep(duration).await;
        let mut guard = timer_counter.lock().unwrap();
        match &mut *guard {
            Some(timer_counter) => {
                if expiration == timer_counter.expiration() {
                    timer_counter.on_expire_timer(dialog_, callback_);
                }
            }
            None => {}
        }
    });
}

pub fn choose_timeout_on_client_transaction_completion(
    // transaction: &Arc<ClientTransaction>,
    // request_session_expires_header: Option<&Header>,
    wanted_uac_timeout: Option<u32>,
    message: &SipMessage,
) -> Option<(u32, Refresher)> {
    if let SipMessage::Response(_, Some(resp_headers), _) = message {
        if let Some(session_expires_header) = header::search(resp_headers, b"Session-Expires", true)
        {
            let session_expires_header_field = session_expires_header.get_value().as_header_field();
            if let Some(session_expires) = session_expires_header_field.as_session_expires() {
                if let Some(refresher) = session_expires.refresher {
                    if refresher == b"uac" {
                        return Some((session_expires.timeout, Refresher::UAC));
                    } else if refresher == b"uas" {
                        return Some((session_expires.timeout, Refresher::UAS));
                    }
                }
            }
        }

        // if let Some(session_expires_header) = request_session_expires_header {
        //     let session_expires_header_field = session_expires_header.get_value().as_header_field();
        //     if let Some(session_expires) = session_expires_header_field.as_session_expires() {
        //         if let Some(refresher) = session_expires.refresher {
        //             if refresher == b"uac" {
        //                 return Some((session_expires.timeout, Refresher::UAC));
        //             }
        //         }
        //     }
        // }

        if let Some(timeout) = wanted_uac_timeout {
            return Some((timeout, Refresher::UAC));
        }
    }

    None
}

/// On 422 error, includes a Min-SE
pub fn choose_timeout_for_server_transaction_response(
    transaction: &Arc<ServerTransaction>,
    previously_supports_timer: bool,
    previous_refresher: Refresher,
) -> Result<Option<(u32, Refresher)>, (u16, &'static [u8], u32)> {
    if let SipMessage::Request(_, Some(headers), _) = transaction.message() {
        let mut explicitly_supports_timer = false;

        if let Some(supported_header) = header::search(headers, b"Supported", true) {
            if supported_header.supports(b"timer") {
                explicitly_supports_timer = true;
            }
        }

        if let Some(session_expires_header) = header::search(headers, b"Session-Expires", true) {
            let session_expires_header_field = session_expires_header.get_value().as_header_field();
            if let Some(session_expires) = session_expires_header_field.as_session_expires() {
                if session_expires.timeout < 90 {
                    return Err((422, b"Session Interval Too Small", 90));
                } else {
                    if let Some(refresher) = session_expires.refresher {
                        if !explicitly_supports_timer {
                            return Err((400, b"Bad Request", 0));
                        }
                        if refresher == b"uac" {
                            return Ok(Some((session_expires.timeout, Refresher::UAC)));
                        } else if refresher == b"uas" {
                            return Ok(Some((session_expires.timeout, Refresher::UAS)));
                        }
                    }

                    if explicitly_supports_timer {
                        return Ok(Some((session_expires.timeout, previous_refresher)));
                    } else if previously_supports_timer {
                        return Ok(Some((session_expires.timeout, Refresher::UAS)));
                    }
                }
            }
        }

        if let Some(min_se_header) = header::search(headers, b"Min-SE", true) {
            if let Ok(min_se) = min_se_header.get_value().to_int() {
                if explicitly_supports_timer {
                    return Ok(Some((min_se, previous_refresher)));
                } else if previously_supports_timer {
                    return Ok(Some((min_se, Refresher::UAS)));
                }
            }
        }

        if explicitly_supports_timer {
            return Ok(Some((900, previous_refresher)));
        } else if previously_supports_timer {
            return Ok(Some((900, Refresher::UAS)));
        }
    }

    Ok(None)
}
