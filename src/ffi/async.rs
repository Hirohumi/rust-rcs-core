use std::{
    sync::{Arc, Mutex},
    task::Waker,
};

pub struct WakerHandle {
    pub waker: Arc<Mutex<Option<Waker>>>,
}

impl WakerHandle {
    pub fn new(waker: &Waker) -> WakerHandle {
        let waker = waker.clone();
        WakerHandle {
            waker: Arc::new(Mutex::new(Some(waker))),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_async_wake_up(handle: *mut WakerHandle) {
    if let Some(handle) = handle.as_mut() {
        let mut guard = handle.waker.lock().unwrap();
        if let Some(waker) = guard.take() {
            waker.wake();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rust_async_destroy_waker(handle: *mut WakerHandle) {
    let _ = Box::from_raw(handle);
}
