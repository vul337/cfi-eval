use super::binary::Elf;
use dfuzz_os::arch::AMD64RegisterSet;
use dfuzz_os::process::*;
use dfuzz_os::signal::*;
use dfuzz_os::spawn::*;
use log::*;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::ops::Range;

#[derive(Debug)]
pub struct Debugger {
    pub process: Process,
    pub thread: Thread,
    breakpoints: HashMap<u64, [u8; 1]>,
}

impl Debugger {
    pub fn vmmap(&self, perm: char) -> Vec<Range<u64>> {
        let vmmap = self.process.to_procfs().unwrap().maps().unwrap();
        vmmap
            .iter()
            .filter_map(|segment| {
                if segment.perms.contains(perm) {
                    Some(segment.address.0..segment.address.1)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn next_event(&mut self) -> Result<AMD64RegisterSet, EventKind> {
        loop {
            self.thread.trace_resume(0).unwrap();
            let event = self.process.trace_next_event().unwrap();
            self.thread = event.thread;
            if event.kind.is_trap() {
                let regs = self.thread.trace_get_registers().unwrap();
                trace!("next_event: stop at {:#x}", regs.rip);
                return Ok(regs);
            }
            match &event.kind {
                EventKind::Suspended(SuspendReason::Signal(signal)) => {
                    let regs = self.thread.trace_get_registers().unwrap();
                    trace!("next_event: signal {:?} at {:#x}", signal, regs.rip);
                    if signal.is_critical() {
                        return Err(event.kind);
                    } else {
                        // Retry
                    }
                }
                _ => return Err(event.kind),
            }
        }
    }

    pub fn set_breakpoint(&mut self, addr: u64) {
        let mut backup = [0];
        self.process.trace_read_memory(addr, &mut backup).unwrap();
        self.breakpoints.insert(addr, backup);
        self.process
            .trace_write_memory_force(addr, &[0xcc])
            .unwrap();
    }

    pub fn remove_breakpoint(&mut self, addr: u64) {
        let backup = self.breakpoints.remove(&addr).expect("unknown breakpoint");
        self.process
            .trace_write_memory_force(addr, &backup)
            .unwrap();
    }

    pub fn disable_breakpoints(&self) {
        for (&addr, backup) in &self.breakpoints {
            self.process.trace_write_memory_force(addr, backup).unwrap();
        }
    }

    pub fn enable_breakpoints(&self) {
        for (&addr, _) in &self.breakpoints {
            self.process
                .trace_write_memory_force(addr, &[0xcc])
                .unwrap();
        }
    }

    pub fn single_step(&self) {
        self.thread.trace_single_step(0).unwrap();
        let event = self.thread.trace_next_event().unwrap();
        assert!(event.kind.is_trap());
    }

    pub fn run_until(&mut self, addrs: &[u64]) -> AMD64RegisterSet {
        for addr in addrs {
            self.set_breakpoint(*addr);
        }
        let mut regs = self.next_event().unwrap();
        for addr in addrs {
            self.remove_breakpoint(*addr);
        }
        regs.rip -= 1;
        self.thread.trace_set_registers(&regs).unwrap();
        regs
    }

    pub fn set_regs(&self, regs: &AMD64RegisterSet) {
        self.thread.trace_set_registers(regs).unwrap();
    }

    pub fn read_u32(&self, addr: u64) -> u32 {
        let mut buf: [u8; 4] = [0; 4];
        self.process.trace_read_memory(addr, &mut buf).unwrap();
        u32::from_ne_bytes(buf)
    }

    pub fn let_it_go(&self) {
        self.process.main_thread().trace_set_options(0).unwrap();
        self.process.send_signal(Signal::SIGSTOP).unwrap();
        panic!("let it go! use `gdb -p {}` to debug the child", self.process.pid())
    }

    pub fn syscall(
        &mut self,
        rip: u64,
        number: u64,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        arg6: u64,
    ) -> u64 {
        let regs_backup = self.thread.trace_get_registers().unwrap();

        // Write "syscall; int3".
        let mut insn_backup = [0; 3];
        self.process
            .trace_read_memory(rip, &mut insn_backup)
            .unwrap();
        self.process
            .trace_write_memory_force(rip, &[0x0f, 0x05, 0xcc])
            .unwrap();

        // Construct args.
        let mut regs = regs_backup.clone();
        regs.rax = number;
        regs.rdi = arg1;
        regs.rsi = arg2;
        regs.rdx = arg3;
        regs.r10 = arg4;
        regs.r8 = arg5;
        regs.r9 = arg6;
        regs.rip = rip;
        self.thread.trace_set_registers(&regs).unwrap();

        // Issue syscall.
        let regs = self.next_event().unwrap();

        // Restore the instruction and the registers.
        self.process
            .trace_write_memory_force(rip, &insn_backup)
            .unwrap();
        self.thread.trace_set_registers(&regs_backup).unwrap();

        regs.rax
    }

    pub fn mprotect(&mut self, rip: u64, addr: u64, size: usize, protection: i32) {
        use dfuzz_os::libc::*;
        let r = self.syscall(
            rip,
            SYS_mprotect as _,
            addr,
            size as _,
            protection as _,
            0,
            0,
            0,
        );
        assert!(r == 0, "cannot mprotect")
    }

    pub fn unwind_stack64(&mut self, mut rbp: u64, level: usize, stack: &mut Vec<u64>) {
        for _ in 0..level {
            let mut buf = [0u8; 16];
            self.process.trace_read_memory(rbp, &mut buf).unwrap();
            let buf: [u64; 2] = unsafe { std::mem::transmute(buf) };
            rbp = buf[0];
            stack.push(buf[1]);
        }
    }

    pub fn disasm<'a>(&self, elf: &'a Elf, addr: u64, len: usize) -> capstone::Instructions<'a> {
        trace!("disasm: {:#x} @ {}", addr, len);
        let mut buf = vec![0; len];
        self.process.trace_read_memory(addr, &mut buf).unwrap();
        elf.disasm.disasm_all(&buf, addr).unwrap()
    }

    pub fn disasm_function<'a>(&self, elf: &'a Elf, pc: u64) -> capstone::Instructions<'a> {
        let symbol = elf.symbol_by_vma(elf.load_to_vma(pc));
        let start = elf.vma_to_load(symbol.st_value);
        self.disasm(elf, start, symbol.st_size as _)
    }

    pub fn new<T: AsRef<OsStr>>(args: &[T]) -> Self {
        let cmd = Command::try_from_args(args).expect("missing program name");

        let mut opts = SpawnOptions::default();
        opts.disable_aslr = true;
        opts.enable_ptrace = true;
        opts.fd_actions = FdActions::new_with_preserve_all();
        let process = cmd.spawn(&opts).expect("cannot fork");
        info!("new process: {}", process.pid());
        process
            .main_thread()
            .trace_set_options(dfuzz_os::libc::PTRACE_O_EXITKILL)
            .unwrap();

        let event = process.trace_next_event().unwrap();
        let thread = event.thread;
        assert!(event.kind.is_trap());

        Self {
            process,
            thread,
            breakpoints: Default::default(),
        }
    }
}
