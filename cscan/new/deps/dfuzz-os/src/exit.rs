//! Check for exit (Ctrl-C and `kill(1)`).

use crate::os::signal;
use std::sync::atomic::{AtomicBool, Ordering};

static EXITING: AtomicBool = AtomicBool::new(false);

extern "C" fn callback(_signal: i32, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    EXITING.store(true, Ordering::Release);
}

/// Returns whether exit is triggered.
pub fn should_exit() -> bool {
    EXITING.load(Ordering::Acquire)
}

/// Enables `should_exit`. Should be called once and only once.
pub fn initialize() {
    unsafe {
        signal::sigaction(libc::SIGTERM, Some(callback));
        signal::sigaction(libc::SIGINT, Some(callback));
    }
}
