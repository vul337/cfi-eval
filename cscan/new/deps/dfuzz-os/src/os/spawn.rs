//! Spawn a new process.
use super::process::Process;
use errno::{errno, Errno};
use failure::Fail;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::AsRawFd;

/// Configure and spawn processes.
#[derive(Debug, Clone)]
pub struct Command {
    program: CString,
    args: Vec<CString>,
    envs: Option<Vec<CString>>,
    /// Used to report error on `exec` when `program` or `args` contains NULL.
    has_null: bool,
}

/// Advanced configurations for spawning a process ([`Command.spawn`]).
///
/// [`Command.spawn`]: struct.Command.html#method.spawn
#[derive(Debug)]
pub struct SpawnOptions {
    /// Call `ptrace(PTRACE_TRACEME)` in the child process.
    pub enable_ptrace: bool,
    /// Disable address space layout randomisation in the child process.
    pub disable_aslr: bool,
    pub fd_actions: FdActions,
}

impl Default for SpawnOptions {
    fn default() -> Self {
        Self {
            enable_ptrace: false,
            disable_aslr: true,
            fd_actions: FdActions::new_empty(),
        }
    }
}

#[derive(Debug)]
enum FdActionKind {
    Preserve,
    Dup(i32),
    Open(CString, i32, i32),
    Suppress,
}

/// Used to manipulate file descriptors in the child process.
///
/// By default, all file descriptors are closed. Use `FdAction` to change the
/// behavior. See also [`SpawnOptions.fd_actions`].
///
/// [`SpawnOptions.fd_actions`]: struct.SpawnOptions.html#structfield.fd_actions
#[derive(Debug)]
pub struct FdActions {
    // Optimize for a small number of actions
    actions: Vec<(i32, FdActionKind)>,
}

impl FdActions {
    /// Constructs an `FdActions` which redirects `/dev/null` to stdin, stdout,
    /// and stderr.
    pub fn new_with_suppress_all() -> Self {
        let actions = vec![
            (libc::STDOUT_FILENO, FdActionKind::Suppress),
            (libc::STDIN_FILENO, FdActionKind::Suppress),
            (libc::STDERR_FILENO, FdActionKind::Suppress),
        ];
        FdActions { actions }
    }

    /// Constructs an `FdActions` which preserves stdin, stdout, and stderr. Note
    /// that multiple reads of stdin is not synchronized, and unexpected
    /// behavior may occur.
    pub fn new_with_preserve_all() -> Self {
        let actions = vec![
            (libc::STDOUT_FILENO, FdActionKind::Preserve),
            (libc::STDIN_FILENO, FdActionKind::Preserve),
            (libc::STDERR_FILENO, FdActionKind::Preserve),
        ];
        FdActions { actions }
    }

    /// Constructs an `FdActions` which only preserves stderr. stdin and stdout
    /// are suppressed.
    pub fn new_with_stderr_only() -> Self {
        let actions = vec![
            (libc::STDOUT_FILENO, FdActionKind::Suppress),
            (libc::STDIN_FILENO, FdActionKind::Suppress),
            (libc::STDERR_FILENO, FdActionKind::Preserve),
        ];
        FdActions { actions }
    }

    /// Constructs an empty `FdActions`, where all fds are closed.
    pub fn new_empty() -> Self {
        FdActions { actions: vec![] }
    }

    /// Close the fd, and make it a duplicate of the `old`-fd. In other words,
    /// replace `fd` with `old`.
    pub fn add_dup(&mut self, new_fd: i32, old_fd: i32) -> &mut Self {
        self.actions.push((new_fd, FdActionKind::Dup(old_fd)));
        self
    }

    /// Close the fd, and redirect `/dev/null` here.
    pub fn add_supress(&mut self, fd: i32) -> &mut Self {
        self.actions.push((fd, FdActionKind::Suppress));
        self
    }

    /// DO NOT close the fd: keep it as-is.
    pub fn add_preserve(&mut self, fd: i32) -> &mut Self {
        self.actions.push((fd, FdActionKind::Preserve));
        self
    }

    /// Close the fd, and replace it with `open(pathname, flags, mode)`.
    pub fn add_open(&mut self, fd: i32, pathname: CString, flags: i32, mode: i32) -> &mut Self {
        self.actions
            .push((fd, FdActionKind::Open(pathname, flags, mode)));
        self
    }

    /// Executes the actions (in the child process).
    unsafe fn execute(&self, ignore_fd: i32) -> Result<(), ()> {
        let mut dev_null_fd = -1i32;

        // Perform actions first, so that the fd won't be closed by accident.
        for (fd, action_kind) in &self.actions {
            match action_kind {
                FdActionKind::Preserve => {}
                FdActionKind::Dup(old) => {
                    // Unset FD_CLOEXEC, which libstd will set for us.
                    if { libc::fcntl(*old, libc::F_SETFD, 0) } == -1 {
                        return Err(());
                    }
                    if libc::dup2(*old, *fd) == -1 {
                        return Err(());
                    }
                }
                FdActionKind::Open(pathname, flags, mode) => {
                    let newfd = libc::open(pathname.as_ptr(), *flags, mode);
                    if newfd == -1 {
                        return Err(());
                    }
                    if libc::dup2(newfd, *fd) == -1 {
                        return Err(());
                    }
                }
                FdActionKind::Suppress => {
                    if dev_null_fd == -1 {
                        dev_null_fd = libc::open(b"/dev/null\0".as_ptr() as _, libc::O_RDWR, 0o666);
                        if dev_null_fd == -1 {
                            return Err(());
                        }
                    }
                    if libc::dup2(dev_null_fd, *fd) == -1 {
                        return Err(());
                    }
                }
            }
        }

        // Close other fds.
        for fd in 0..libc::sysconf(libc::_SC_OPEN_MAX) as _ {
            if fd != ignore_fd
                && self
                    .actions
                    .iter()
                    .find(|(action_fd, _action_kind)| *action_fd == fd)
                    .is_none()
            {
                libc::close(fd);
            }
        }

        Ok(())
    }
}

/// Error type for spawning.
#[derive(Debug, Fail, Clone, Copy, FromPrimitive)]
#[repr(u8)]
pub enum Error {
    #[fail(display = "program path or arguments contains NULL")]
    HasNull,
    #[fail(display = "cannot enable coredump")]
    Coredump,
    #[fail(display = "cannot enable tracing on child process")]
    PtraceMe,
    #[fail(display = "cannot disable ASLR")]
    Aslr,
    #[fail(display = "cannot reset signal mask")]
    Sigmask,
    #[fail(display = "cannot find the executable, interpreter, or shared library")]
    NotFound,
    #[fail(display = "path resolution is denied, or the execution permission is missing")]
    PermissionDenied,
    #[fail(display = "executable format is not recognized")]
    NotExecutable,
    #[fail(display = "insufficient system resource")]
    FdAction,
    #[fail(display = "cannot complete file descriptor actions")]
    InsufficientResource,
    #[fail(display = "other execution errors for execve")]
    OtherExec,
}

impl Command {
    /// Constructs a new `Command` for launching the program at
    /// path `program`, with the following default configuration:
    ///
    /// * No arguments to the program
    /// * Inherit the current process's environment
    /// * Inherit the current process's working directory
    /// * `ptrace` disabled
    pub fn new<S: AsRef<OsStr>>(program: S) -> Command {
        let mut has_null = false;
        let program = to_cstring(program.as_ref(), &mut has_null);
        Command {
            has_null,
            program,
            envs: None,
            args: Default::default(),
        }
    }

    /// Constructs a new `Command`, where the program and args are `array[0],
    /// array[1], ...`.
    ///
    /// # Panics
    /// If program name is missing. (`args` doesn't has any item.)
    pub fn new_from_args<U: AsRef<OsStr>, I: IntoIterator<Item = U>>(args: I) -> Command {
        let mut args = args.into_iter();
        let mut cmd = Command::new(args.next().expect("missing program name"));
        cmd.args(args);
        cmd
    }

    /// Adds an argument to pass to the program.
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Command {
        self.args.push(to_cstring(arg.as_ref(), &mut self.has_null));
        self
    }

    /// Adds multiple arguments to pass to the program.
    pub fn args<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(&mut self, args: I) -> &mut Command {
        let mut has_null = self.has_null;
        self.args.extend(
            args.into_iter()
                .map(|arg| to_cstring(arg.as_ref(), &mut has_null)),
        );
        self.has_null = has_null;
        self
    }

    /// Replaces the environment variable of the target process.
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Command
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut has_null = self.has_null;

        let mut envs = vec![];
        for (key, value) in vars {
            let key = key.as_ref();
            let value = value.as_ref();

            let mut env = OsString::with_capacity(key.len() + value.len() + 2);
            env.push(key);
            env.push("=");
            env.push("value");

            envs.push(to_cstring(env.as_ref(), &mut has_null));
        }

        self.envs = Some(envs);
        self
    }

    /// Really do the fork & exec stuff.
    unsafe fn exec(&self, opts: &SpawnOptions) -> Result<(u32, File), Error> {
        if self.has_null {
            return Err(Error::HasNull);
        }

        // Prepare args.
        let program = self.program.as_bytes_with_nul().as_ptr();
        let argv_user = self.args.iter().map(|arg| arg.as_bytes_with_nul().as_ptr());
        let args: Vec<_> = std::iter::once(program)
            .chain(argv_user)
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Prepare envs.
        let envs = self.envs.as_ref().map(|envs| {
            envs.iter()
                .map(|env| env.as_bytes_with_nul().as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>()
        });

        let (reader, writer) = match pipe2() {
            Ok(pipes) => pipes,
            Err(_errno) => return Err(Error::InsufficientResource),
        };

        let ret = libc::fork();
        if ret != 0 {
            return match ret {
                // Fork has failed.
                -1 => Err(Error::InsufficientResource),
                // We are in the parent process.
                pid => Ok((pid as _, reader)),
            };
        }

        // fork() = 0: we are in the child process.
        drop(reader);

        if opts.enable_ptrace {
            // Enable coredump. Processes that are not dumpable can not
            // be attached via PTRACE_ATTACH.
            let suid_dump_user = 1;
            if libc::prctl(libc::PR_SET_DUMPABLE, suid_dump_user, 0, 0, 0) == -1 {
                child_panic(writer, Error::Coredump);
            }

            // Enable ptrace; returns EPERM when already traced.
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                child_panic(writer, Error::PtraceMe);
            }
        }

        if opts.disable_aslr {
            let persona_get = 0xffff_ffff;
            let addr_no_randomize = 0x0004_0000;
            let persona = libc::personality(persona_get) as u64;
            if libc::personality(addr_no_randomize | persona) == -1 {
                child_panic(writer, Error::Aslr);
            }
        }

        // We want to keep the writer to report errors, until `execve` succeeds
        // and the kernel automatically close the writer fd.
        let ignore_fd = writer.as_raw_fd();
        if opts.fd_actions.execute(ignore_fd).is_err() {
            child_panic(writer, Error::FdAction);
        }

        // Clear sigmask.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        if libc::pthread_sigmask(libc::SIG_SETMASK, &set, std::ptr::null_mut()) != 0 {
            child_panic(writer, Error::Sigmask);
        }

        // Do exec (finally)!
        match envs {
            None => libc::execv(program as _, args.as_slice().as_ptr() as _),
            Some(envs) => libc::execve(
                program as _,
                args.as_slice().as_ptr() as _,
                envs.as_slice().as_ptr() as _,
            ),
        };

        // If we have reached here, exec has encountered error.
        let errno = errno();
        let reason = match errno.0 {
            libc::ENOENT => Error::NotFound,
            libc::EACCES => Error::PermissionDenied,
            libc::ENOMEM => Error::InsufficientResource,
            _ => Error::OtherExec,
        };
        child_panic(writer, reason);
    }

    /// Spawns a new process.
    pub fn spawn(&self, opts: &SpawnOptions) -> Result<Process, Error> {
        let (pid, mut reader) = unsafe { self.exec(&opts) }?;

        // Read the pipe for error in child process.
        use std::io::Read;
        let mut buf = [0u8; 1];
        let len = reader
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("cannot determine child state: {}", e));

        if len == 0 {
            // Everything goes smoothly. The child process is replaced with the
            // target program, and the pipe is closed without sending anything.
            Ok(pid.into())
        } else {
            // Errors occur while preparing or doing execve. The cause is sent
            // through the pipe.
            Err(Error::from_u8(buf[0]).expect("unexpected Error variant"))
        }
    }
}

fn to_cstring(s: &OsStr, has_null: &mut bool) -> CString {
    CString::new(s.as_bytes()).unwrap_or_else(|_| {
        *has_null = true;
        CString::new("<null>").unwrap()
    })
}

/// Returns (reader, writer)
unsafe fn pipe2() -> Result<(File, File), Errno> {
    let mut fds = [0; 2];
    match libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) {
        0 => (),
        _error => return Err(errno()),
    }
    use std::os::unix::io::FromRawFd;
    let reader = File::from_raw_fd(fds[0]);
    let writer = File::from_raw_fd(fds[1]);
    Ok((reader, writer))
}

fn child_panic(mut file: File, error: Error) -> ! {
    use std::io::Write;
    let _ = file.write(&[error as u8]);
    eprintln!(
        "cannot prepare for execution in the child process: {}",
        error
    );
    unsafe {
        libc::abort();
    }
}
