//! Processes, threads and events.
//!
//! Invoke [`wait`] to obtain an [`Event`].
//!
//! [`wait`]: fn.wait.html
//! [`Event`]: struct.Event.html

use super::arch::AMD64RegisterSet;
use super::signal::Signal;
use bitflags::bitflags;
use errno::{errno, set_errno, Errno};
use failure::Fail;
use log::*;
use std::mem::MaybeUninit;
use std::path::Path;

pub type RegisterSet = AMD64RegisterSet;

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IoVec {
    base: u64,
    len: usize,
}

impl IoVec {
    unsafe fn from_buffer(buf: &[u8]) -> Self {
        Self {
            base: buf.as_ptr() as _,
            len: buf.len(),
        }
    }

    fn new(base: u64, len: usize) -> Self {
        Self { base, len }
    }
}

/// The terminate reasons for a process vanished from the OS or in limbo.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TerminateReason {
    Exit { status: i32 },
    Signal { signal: Signal, has_coredump: bool },
}

impl TerminateReason {
    /// Returns `Some(result)` if the status denotes terminated process. Returns
    /// `None` if not this case.
    fn decode(status: i32) -> Option<Self> {
        unsafe {
            if libc::WIFEXITED(status) {
                // Bits:
                // - 0-6: 0
                // - 7
                // - 8-15: exit code
                //
                let status = libc::WEXITSTATUS(status);
                Some(TerminateReason::Exit { status })
            } else if libc::WIFSIGNALED(status) {
                // Bits:
                // - 0-6: terminal signal in [1, 0x7f)
                // - 7: have coredump?
                Some(TerminateReason::Signal {
                    signal: Signal::coerce_from(libc::WTERMSIG(status)),
                    has_coredump: libc::WCOREDUMP(status),
                })
            } else {
                None
            }
        }
    }
}

/// The child of a fork-ish operation, i.e. a new thread or process.
///
/// It is reported when [`SuspendReason::Fork`] happens.
///
/// [`SuspendReason::Fork`]: enum.SuspendReason.html
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkChild {
    Thread(Thread),
    Process(Process),
}

impl ForkChild {
    fn from_tid(parent: Thread, child_id: u32) -> Self {
        let child_thread = child_id.into();
        if parent.same_process(child_thread) {
            ForkChild::Thread(child_thread)
        } else {
            ForkChild::Process(child_id.into())
        }
    }
}

/// Kinds for fork-ish syscalls.
///
/// A process can be created by `vfork`/`fork`/`clone`, and a thread can be
/// created by `clone`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForkKind {
    Fork,
    Clone,
    VFork,
    VForkDone,
}

/// The process has been suspended, usually because of an event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuspendReason {
    Signal(Signal),
    Terminate(TerminateReason),
    Syscall,
    Exec,
    Fork { child: ForkChild, kind: ForkKind },
    SecComp,
    Unknown,
}

impl SuspendReason {
    /// Returns `Some(result)` if the status denotes suspended process. Returns
    /// `None` if not this case.
    fn decode(thread: Thread, status: i32) -> Option<Self> {
        if !unsafe { libc::WIFSTOPPED(status) } {
            return None;
        }

        // Bits 0-7 = 0x7f
        let signal = unsafe { libc::WSTOPSIG(status) }; // Bits 8-15
        let extension = status >> 16; // Bits 16-31

        let reason = if signal == libc::SIGTRAP | 0x80 {
            // Situation: syscall (PTRACE_O_TRACESYSGOOD)
            // Bits:
            // - 8-14: SIGTRAP
            // - 15: 1 (syscall)
            // - 16-31: 0
            SuspendReason::Syscall
        } else if extension == 0 {
            // Situation: signal
            // Bits:
            // - 8-14: signal number
            // - 15
            // - 16-31: 0
            SuspendReason::Signal(Signal::coerce_from(signal))
        } else {
            // Situation: ptrace event
            // Bits:
            // - 8-14: SIGTRAP
            // - 15: 0
            // - 16-31: event number
            match extension {
                libc::PTRACE_EVENT_EXIT => Self::decode_exit(thread),
                libc::PTRACE_EVENT_EXEC => SuspendReason::Exec,
                libc::PTRACE_EVENT_SECCOMP => SuspendReason::SecComp,
                libc::PTRACE_EVENT_FORK
                | libc::PTRACE_EVENT_VFORK
                | libc::PTRACE_EVENT_VFORK_DONE
                | libc::PTRACE_EVENT_CLONE => Self::decode_fork(thread, extension),
                _ => panic!(
                    "unexpected ptrace event for {}: signal = {}, extension = {}",
                    thread.tid(),
                    signal,
                    extension
                ),
            }
        };
        Some(reason)
    }

    fn decode_exit(thread: Thread) -> Self {
        match thread.trace_get_event_message() {
            Ok(exit_code) => TerminateReason::decode(exit_code as _)
                .map(SuspendReason::Terminate)
                .unwrap_or_else(|| {
                    panic!(
                        "non-terminal code on PTRACE_EVENT_EXIT, code = {}",
                        exit_code
                    )
                }),
            Err(e) => {
                debug!(target: "trace",
                       "cannot to get event for PTRACE_EVENT_EXIT: {}", e);
                SuspendReason::Unknown
            }
        }
    }

    fn decode_fork(thread: Thread, extension: i32) -> Self {
        let kind = match extension {
            libc::PTRACE_EVENT_FORK => ForkKind::Fork,
            libc::PTRACE_EVENT_VFORK => ForkKind::VFork,
            libc::PTRACE_EVENT_VFORK_DONE => ForkKind::VForkDone,
            libc::PTRACE_EVENT_CLONE => ForkKind::Clone,
            _ => unreachable!(),
        };
        match thread.trace_get_event_message() {
            Ok(child_tid) => SuspendReason::Fork {
                child: ForkChild::from_tid(thread, child_tid as _),
                kind,
            },
            Err(e) => {
                debug!(target: "trace",
                       "cannot to get event for {:?}: {}", kind, e);
                SuspendReason::Unknown
            }
        }
    }
}

/// Thread event details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventKind {
    Terminated(TerminateReason),
    Suspended(SuspendReason),
    Resumed,
}

impl EventKind {
    /// Decode the waitpid event. It may fail only when `Event::Terminated` is occurred.
    fn decode(thread: Thread, status: i32) -> EventKind {
        if unsafe { libc::WIFCONTINUED(status) } {
            // Bits: 0-15 = 0xffff
            EventKind::Resumed
        } else if let Some(reason) = TerminateReason::decode(status) {
            EventKind::Terminated(reason)
        } else if let Some(reason) = SuspendReason::decode(thread, status) {
            EventKind::Suspended(reason)
        } else {
            panic!("unexpected wait status");
        }
    }

    /// Returns whether the event is SIGTRAP.
    pub fn is_trap(&self) -> bool {
        if let EventKind::Suspended(SuspendReason::Signal(Signal::SIGTRAP)) = self {
            true
        } else {
            false
        }
    }
}

/// Thread events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    /// The thread where the event occurred.
    pub thread: Thread,
    /// Details of the event.
    pub kind: EventKind,
}

impl Event {
    /// Automatically resume suspended thread.
    ///
    /// # Behavior
    /// * SIGSTOP / SIGTRAP: resume with no signal
    /// * Other signals: resume with the original signal
    /// * Fork: resume the new process or thread
    pub fn resume(&self) -> Result<(), TraceError> {
        if let EventKind::Suspended(ref reason) = self.kind {
            match reason {
                &SuspendReason::Signal(signal) => {
                    if signal == Signal::SIGSTOP || signal == Signal::SIGTRAP {
                        // SIGSTOP and SIGTRAP is used for debugging. It's unlikely that
                        // other processes will send this signal.
                        self.thread.trace_resume(0)
                    } else {
                        self.thread.trace_resume(signal as _)
                    }
                }
                SuspendReason::Fork { child, kind } => {
                    let _ = kind;
                    match child {
                        ForkChild::Thread(thread) => thread.trace_resume(0)?,
                        ForkChild::Process(process) => {
                            // The only thread of a newly created process is its main thread.
                            process.main_thread().trace_resume(0)?
                        }
                    }
                    self.thread.trace_resume(0)
                }
                _ => self.thread.trace_resume(0),
            }
        } else {
            Ok(())
        }
    }

    fn new(tid: u32, status: i32) -> Self {
        let thread = Thread::from(tid);
        let kind = EventKind::decode(thread, status);
        Self { thread, kind }
    }
}

/// Error returned by `wait`.
#[derive(Debug, Fail)]
pub enum WaitError {
    #[fail(display = "no child process")]
    NoChild,
    #[fail(display = "no event available")]
    NoEvent,
}

/// Checks for the next process event.
///
/// Blocking mode (`WaitOptions::NONBLOCK` is NOT set):
/// * Wait and returns `Ok(Event)` denoting the event;
/// * Immediately returns `Err(WaitError::NoChild)` if no child exists.
///
/// Nonblocking mode (`WaitOptions::NONBLOCK` is set):
/// * Returns `Ok(event)` if an event is available;
/// * Returns `Err(NoChild)` if no child exists or the child is filtered out;
/// * Returns `Err(NoEvent)` if no event is immediately available.
pub fn wait(target: WaitTarget, options: WaitOptions) -> Result<Event, WaitError> {
    let mut status = 0;
    loop {
        match unsafe { libc::waitpid(target.0, &mut status as _, options.bits()) } {
            // Handle error.
            -1 => {
                let err = errno();
                match err.0 {
                    // No child process. All pending events are processed.
                    libc::ECHILD => return Err(WaitError::NoChild),
                    // Interrupted by signal: retry.
                    libc::EINTR => continue,
                    // Other error: shouldn't happen.
                    _ => panic!("unknown waitpid error: {}", err),
                }
            }
            // Have child process, but no state change. Implies that all
            // pending events are processed.
            0 => return Err(WaitError::NoEvent),
            pid => {
                return Ok(Event::new(pid as _, status));
            }
        }
    }
}

/// Helper for specifying target(s) for `wait`.
pub struct WaitTarget(i32);

impl WaitTarget {
    /// Wait for any child process.
    pub fn any() -> Self {
        Self(-1)
    }

    /// Wait for any child process whose process group ID is equal to that of
    /// the calling process.
    pub fn same_pgid() -> Self {
        Self(0)
    }

    /// Wait for any child process whose process group ID is equal to `pgid`.
    pub fn by_pgid(pgid: u32) -> Self {
        Self(-(pgid as i32))
    }

    /// Wait for the child whose process ID is equal to `pid`.
    pub fn by_pid(pid: u32) -> Self {
        Self(pid as _)
    }
}

bitflags! {
    /// Options for invoking `wait`.
    pub struct WaitOptions : i32 {
        /// Only wait child of current thread. If not specified, waits for child
        /// of all threads inside current process.
        const ONLY_CURRENT_THREAD_CHILD = libc::__WNOTHREAD;

        /// Do not wait for the next event. Return immediately even if no event
        /// is available.
        const NONBLOCK = libc::WNOHANG;

        /// Wait for both process and thread events. If not specified, only wait
        /// for process events.
        const PROCESS_AND_THREADS = libc::__WALL;

        /// Wait for thread events only.
        const THREAD_ONLY = libc::__WCLONE;
    }
}

impl WaitOptions {
    /// Recommended options if `ptrace` is enabled.
    pub fn default_trace() -> WaitOptions {
        WaitOptions::PROCESS_AND_THREADS | WaitOptions::ONLY_CURRENT_THREAD_CHILD
    }

    /// Recommended options for just waiting for exit status.
    pub fn default_exit() -> WaitOptions {
        WaitOptions::ONLY_CURRENT_THREAD_CHILD
    }
}

/// Error type for tracing a process.
#[derive(Debug, Fail)]
pub enum TraceError {
    #[fail(display = "invalid signal")]
    InvalidSignal,
    #[fail(display = "invalid remote address or length")]
    InvalidRemoteAddress,
    #[fail(display = "process not found")]
    NotFound,
    #[fail(display = "permission denied")]
    PermissionDenied,
}

/// Thin wrapper for raw thread id.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Thread {
    tid: u32,
}

impl Thread {
    /// Returns the thread id of calling thread.
    pub fn current_tid() -> u32 {
        unsafe { libc::syscall(libc::SYS_gettid) as u32 }
    }

    /// Returns the thread id (`gettid()` or `Pid` in procfs)
    pub fn tid(self) -> u32 {
        self.tid
    }

    /// Returns the process which contains current thread.
    pub fn to_process(self) -> Result<Process, procfs::ProcError> {
        self.to_procfs()
            .and_then(|process| process.status())
            .and_then(|status| Ok(Process::from(status.tgid as u32)))
    }

    /// Returns the next event by `wait(tid)`.
    pub fn trace_next_event(self) -> Result<Event, WaitError> {
        wait(WaitTarget::by_pid(self.tid()), WaitOptions::THREAD_ONLY)
    }

    /// PTRACE_DETACH. `signal` = 0: continue without signaling
    pub fn trace_detach(self, signal: i32) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_DETACH, None, signal as _)
            .map(|_| ())
    }

    /// PTRACE_CONT. `signal` = 0: continue without signaling
    pub fn trace_resume(self, signal: i32) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_CONT, None, signal as _)
            .map(|_| ())
    }

    /// PTRACE_SETOPTIONS.
    ///
    /// Note that a child process (thread) always inherits its parent's option.
    /// It's no need to set the options again on a newly created child.
    ///
    /// The ptrace options are stored in `task_struct.ptrace`. When creating a
    /// new task, `_do_fork` finally invokes `arch_dup_task_struct`, where
    /// `task_struct` is directly copied.
    pub fn trace_set_options(self, options: i32) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_SETOPTIONS, None, options as _)
            .map(|_| ())
    }

    /// PTRACE_GETEVENTMSG.
    pub fn trace_get_event_message(self) -> Result<usize, TraceError> {
        let mut msg = 0usize;
        self.ptrace(libc::PTRACE_GETEVENTMSG, None, &mut msg as *mut _ as _)?;
        Ok(msg)
    }

    /// PTRACE_GET_REGS.
    pub fn trace_get_registers(self) -> Result<RegisterSet, TraceError> {
        let mut r = MaybeUninit::uninit();
        self.ptrace(libc::PTRACE_GETREGS, None, r.as_mut_ptr() as _)?;
        Ok(unsafe { r.assume_init() })
    }

    /// PTRACE_SET_REGS.
    pub fn trace_set_registers(self, regs: &RegisterSet) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_SETREGS, None, regs as *const _ as _)?;
        Ok(())
    }

    /// PTRACE_SINGLESTEP.
    pub fn trace_single_step(self, signal: i32) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_SINGLESTEP, None, signal as _)
            .map(|_| ())
    }

    /// PTRACE_SYSCALL.
    pub fn trace_syscall(self, signal: i32) -> Result<(), TraceError> {
        self.ptrace(libc::PTRACE_SYSCALL, None, signal as _)
            .map(|_| ())
    }

    /// Returns whether the thread exists in the kernel.
    pub fn exists(self) -> bool {
        self.to_procfs()
            .map(|proc| proc.stat.state != 'Z') // Zombie process does not exist
            .unwrap_or(false) // The process has been reaped
    }

    /// Returns whether `others` and `self` are inside the same process.
    pub fn same_process(self, others: Thread) -> bool {
        let path = format!("/proc/{}/task/{}", self.tid, others.tid);
        Path::new(path.as_str()).exists()
    }

    /// Suspend current thread. Current thread will not stop immediately,
    /// perform `wait` to wait for change of state.
    pub fn suspend(self, pid: u32) -> Result<(), TraceError> {
        self.send_signal(Signal::SIGSTOP, pid)
    }

    /// Sends a signal to the thread.
    pub fn send_signal(self, signal: Signal, pid: u32) -> Result<(), TraceError> {
        if unsafe { libc::syscall(libc::SYS_tgkill, pid, self.tid, signal as i32) } == 0 {
            return Ok(());
        }
        Err(match errno() {
            Errno(libc::EINVAL) => TraceError::InvalidSignal,
            Errno(libc::EPERM) => TraceError::PermissionDenied,
            Errno(libc::ESRCH) => TraceError::NotFound,
            _ => unreachable!(), // Corner case: EAGAIN could be returned on real-time signal
        })
    }

    /// Returns info from procfs.
    pub fn to_procfs(self) -> procfs::ProcResult<procfs::Process> {
        procfs::Process::new(self.tid as _)
    }

    fn ptrace(
        self,
        request: libc::c_uint,
        addr: Option<usize>,
        data: usize,
    ) -> Result<libc::c_long, TraceError> {
        set_errno(Errno(0));
        let addr = addr.unwrap_or(0);
        let ret = unsafe { libc::ptrace(request, self.tid, addr, data) };
        let errno = errno();
        match errno.0 {
            0 => Ok(ret),
            libc::EPERM => Err(TraceError::PermissionDenied),
            libc::EIO | libc::EINVAL | libc::EFAULT => Err(TraceError::InvalidRemoteAddress),
            libc::ESRCH => {
                if self.exists() {
                    panic!("ptrace invoked on thread with unexpected state")
                } else {
                    Err(TraceError::NotFound)
                }
            }
            _ => panic!("unexpect ptrace error: {}", errno),
        }
    }
}

/// Thin wrapper for raw process id.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct Process {
    pid: u32,
}

impl Process {
    /// Returns the process id of current process.
    pub fn current_pid() -> u32 {
        unsafe { libc::getpid() as _ }
    }

    /// Returns the process id (`getpid()` or `Tgid` in procfs)
    pub fn pid(self) -> u32 {
        self.pid
    }

    /// Returns the main thread object of current process.
    pub fn main_thread(self) -> Thread {
        Thread { tid: self.pid }
    }

    /// Sends a signal to the process.
    pub fn send_signal(self, signal: Signal) -> Result<(), TraceError> {
        if unsafe { libc::kill(self.pid as _, signal as i32) } == 0 {
            return Ok(());
        }
        Err(match errno() {
            Errno(libc::EINVAL) => TraceError::InvalidSignal,
            Errno(libc::EPERM) => TraceError::PermissionDenied,
            Errno(libc::ESRCH) => TraceError::NotFound,
            _ => unreachable!(),
        })
    }

    /// Terminate the process.
    pub fn terminate(self) {
        if let Err(e) = self.send_signal(Signal::SIGKILL) {
            warn!(target: "trace", "cannot terminate {}: {}", self.pid, e);
        }
    }

    /// Returns `Some(TerminateReason)`. Returns `None` if still running. Panics
    /// on invalid pid.
    pub fn get_terminate_reason(self) -> Option<TerminateReason> {
        match wait(
            WaitTarget::by_pid(self.pid),
            WaitOptions::NONBLOCK | WaitOptions::ONLY_CURRENT_THREAD_CHILD,
        ) {
            Ok(event) => {
                if let EventKind::Terminated(reason) = event.kind {
                    Some(reason)
                } else {
                    None
                }
            }
            Err(WaitError::NoChild) => panic!("waiting for nonexist child"),
            Err(WaitError::NoEvent) => None,
        }
    }

    /// Returns info from procfs.
    pub fn to_procfs(self) -> procfs::ProcResult<procfs::Process> {
        self.main_thread().to_procfs()
    }

    /// Returns the next event by `wait(pid, __WALL)`.
    pub fn trace_next_event(self) -> Result<Event, WaitError> {
        wait(
            WaitTarget::by_pid(self.pid()),
            WaitOptions::PROCESS_AND_THREADS,
        )
    }

    /// Read or write multiple memory regions.
    pub fn trace_read_write_memory_vectorized(
        self,
        write_mode: bool,
        local: &[IoVec],
        remote: &[IoVec],
    ) -> Result<usize, TraceError> {
        let r = if write_mode {
            unsafe {
                libc::process_vm_writev(
                    self.pid() as _,
                    local.as_ptr() as _,
                    local.len() as _,
                    remote.as_ptr() as _,
                    remote.len() as _,
                    0,
                )
            }
        } else {
            unsafe {
                libc::process_vm_readv(
                    self.pid() as _,
                    local.as_ptr() as _,
                    local.len() as _,
                    remote.as_ptr() as _,
                    remote.len() as _,
                    0,
                )
            }
        };

        if r != -1 {
            return Ok(r as _);
        }

        let errno = errno();
        Err(match errno.0 {
            libc::EFAULT => TraceError::InvalidRemoteAddress,
            libc::EPERM => TraceError::PermissionDenied,
            libc::ESRCH => TraceError::NotFound,
            _ => unreachable!(), // ENOMEM, EINVAL
        })
    }

    /// Reads memory.
    pub fn trace_read_memory(self, base: u64, buf: &mut [u8]) -> Result<(), TraceError> {
        let local = [unsafe { IoVec::from_buffer(buf) }];
        let remote = [IoVec::new(base, buf.len())];
        let len =
            self.trace_read_write_memory_vectorized(false /* write_mode */, &local, &remote)?;
        if len != buf.len() {
            Err(TraceError::InvalidRemoteAddress)
        } else {
            Ok(())
        }
    }

    /// Writes memory; memory protection is respected.
    pub fn trace_write_memory(self, base: u64, buf: &[u8]) -> Result<(), TraceError> {
        let local = [unsafe { IoVec::from_buffer(buf) }];
        let remote = [IoVec::new(base, buf.len())];
        let len =
            self.trace_read_write_memory_vectorized(true /* write_mode */, &local, &remote)?;
        if len != buf.len() {
            Err(TraceError::InvalidRemoteAddress)
        } else {
            Ok(())
        }
    }

    /// PTRACE_PEEKDATA: read memory in word.
    pub fn trace_peek(self, base: u64) -> Result<usize, TraceError> {
        Ok(self
            .main_thread()
            .ptrace(libc::PTRACE_PEEKDATA, Some(base as _), 0)? as _)
    }

    /// PTRACE_POKEDATA: write memory in word.
    pub fn trace_poke(self, base: u64, data: usize) -> Result<(), TraceError> {
        self.main_thread()
            .ptrace(libc::PTRACE_POKEDATA, Some(base as _), data)?;
        Ok(())
    }

    /// Write memory *without* checking protection. Slower, but more robust.
    pub fn trace_write_memory_force(self, mut base: u64, mut buf: &[u8]) -> Result<(), TraceError> {
        const WORD_SIZE: usize = std::mem::size_of::<usize>();

        // As the write operation works in word level, we need to align the
        // buffer first. Here's an example request, where:
        // WORD_SIZE = 8, base = 5, buf.len() = 13.
        //
        // | 0 1 2 3 4 5 6 7 | 8 9 a b c d e f |
        // |           x x x | x x x x x x x x |
        // | 0 1 2 3 4 5 6 7 | 8 9 a b c d e f |
        // | x x             |                 |
        while !buf.is_empty() {
            let reminder = base as usize % WORD_SIZE;
            if reminder != 0 || buf.len() < WORD_SIZE {
                // We need to read the buffer back.
                let aligned = base - reminder as u64;
                let mut word = self.trace_peek(aligned)?.to_ne_bytes();

                // Partially update the buffer.
                let begin = reminder;
                let end = std::cmp::min(begin + buf.len(), WORD_SIZE);
                let len = end - begin;
                word[begin..end].copy_from_slice(&buf[0..len]);

                self.trace_poke(aligned, usize::from_ne_bytes(word))?;
                base += len as u64;
                buf = &buf[len..];
            } else {
                let mut word = [0; WORD_SIZE];
                word.copy_from_slice(&buf[0..WORD_SIZE]);
                self.trace_poke(base, usize::from_ne_bytes(word))?;
                base += WORD_SIZE as u64;
                buf = &buf[WORD_SIZE..];
            }
        }

        Ok(())
    }
}

impl From<u32> for Process {
    fn from(pid: u32) -> Process {
        Process { pid }
    }
}

impl From<u32> for Thread {
    fn from(tid: u32) -> Thread {
        Thread { tid }
    }
}
