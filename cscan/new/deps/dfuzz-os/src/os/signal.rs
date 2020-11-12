//! UNIX signal related operations.

use errno::{errno, set_errno};
use std::fmt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;

/// Sender of the UnixStream pair for sending signals.
static mut SIGNAL_TX: i32 = -1;

unsafe extern "C" fn signal_stream_writer(
    signo: libc::c_int,
    _info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    let prev_errno = errno();
    let buf = signo as u8;
    let bytes_written = libc::write(SIGNAL_TX, &buf as *const _ as _, 1);
    assert_eq!(bytes_written, 1, "cannot report signal");
    set_errno(prev_errno);
}

/// Registers a handler for `signals`. If such signal is received, the handler
/// writes one-byte denoting the signal number to the returned `UnixStream`.
///
/// # Panics
/// * If this function is invoked a second time.
/// * If fails to register a signal handler.
pub fn initialize_signal_stream(signals: &[Signal]) -> UnixStream {
    unsafe {
        // Best-effort sanity check. May have false negatives if multi-threaded.
        assert_eq!(SIGNAL_TX, -1, "signal handler is already initialized");

        let (tx, rx) = UnixStream::pair().unwrap();
        tx.set_nonblocking(true).unwrap();
        SIGNAL_TX = tx.as_raw_fd();
        std::mem::forget(tx);

        for &signal in signals {
            sigaction(signal as _, Some(signal_stream_writer));
        }

        rx
    }
}

/// Restores the handler for `signals`, and close the internal `UnixStream`.
pub fn close_signal_stream(signals: &[Signal]) {
    unsafe {
        assert_ne!(SIGNAL_TX, -1, "Signal handler is not initialized");
        assert_eq!(libc::close(SIGNAL_TX), 0);
        SIGNAL_TX = -1;

        for &signal in signals {
            sigaction(signal as _, None);
        }
    }
}

/// Register/deregister signal handler. Use `Some(handler)` to register, and
/// `None` to deregister. Panics on failure.
///
/// # Safety
/// The callback is directly invoked by the kernel on the specified signal. The
/// callback should be signal-safe. See [`signal-safety(7)`] for details.
///
/// [`signal-safety(7)`]: http://man7.org/linux/man-pages/man7/signal-safety.7.html
pub unsafe fn sigaction(
    signal: Signal,
    callback: Option<unsafe extern "C" fn(i32, *mut libc::siginfo_t, *mut libc::c_void)>,
) -> libc::sigaction {
    let mut new: libc::sigaction = std::mem::zeroed();
    match callback {
        Some(callback) => {
            new.sa_flags = libc::SA_RESTART | libc::SA_SIGINFO;
            new.sa_sigaction = callback as _;
        }
        None => {
            new.sa_sigaction = libc::SIG_DFL;
        }
    }

    let mut prev: libc::sigaction = std::mem::zeroed();
    assert_eq!(
        libc::sigaction(signal as i32, &new, &mut prev),
        0,
        "cannot manipulate signal handler"
    );
    prev
}

macro_rules! signal_struct {
    (pub enum $struct_name:ident {
        $($name:ident),*
    }) => {
        /// UNIX signals.
        #[repr(i32)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $struct_name {
            $(
                $name = libc::$name,
            )*
        }

        impl $struct_name {
            /// Convert to string.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(
                        $struct_name::$name => stringify!(name),
                    )*
                }
            }
        }

        impl std::convert::TryFrom<i32> for $struct_name {
            type Error = i32;

            /// Returns `Err(raw_value)` if the variant is not found. Returns
            /// `Ok(signal)` otherwise.
            fn try_from(value: i32) -> Result<Self, Self::Error> {
                match value {
                    $(
                        libc::$name => Ok($struct_name::$name),
                    )*
                    _ => Err(value),
                }
            }
        }
    };
}

signal_struct! {
    pub enum Signal {
        SIGABRT,
        SIGALRM,
        SIGBUS,
        SIGCHLD,
        SIGCONT,
        SIGFPE,
        SIGHUP,
        SIGILL,
        SIGINT,
        SIGIO,
        SIGKILL,
        SIGPIPE,
        SIGPROF,
        SIGPWR,
        SIGQUIT,
        SIGSEGV,
        SIGSTKFLT,
        SIGSTOP,
        SIGTSTP,
        SIGSYS,
        SIGTERM,
        SIGTRAP,
        SIGTTIN,
        SIGTTOU,
        SIGURG,
        SIGUSR1,
        SIGUSR2,
        SIGVTALRM,
        SIGXCPU,
        SIGXFSZ,
        SIGWINCH
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.as_str(), *self as i32)
    }
}

impl Signal {
    /// Force converting from a scalar. Panics if fail.
    pub fn coerce_from(signal: i32) -> Self {
        use std::convert::TryFrom;
        Self::try_from(signal).expect("unknown signal")
    }

    /// Checks whether the signal implies a bug.
    pub fn is_critical(self) -> bool {
        match self {
            Signal::SIGILL => true,  // LLVM's unreachable code
            Signal::SIGFPE => true,  // Divide by zeroed
            Signal::SIGSEGV => true, // Invalid memory access
            Signal::SIGBUS => true,  // Invalid memory address
            Signal::SIGABRT => true, // abort()
            Signal::SIGSYS => true,  // Bad syscall
            _ => false,
        }
    }
}
