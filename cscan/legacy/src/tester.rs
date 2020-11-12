use super::binary::Elf;
use super::debugger::Debugger;
use super::disasm;
use dfuzz_os::arch::AMD64RegisterSet;
use dfuzz_os::process::*;
use dfuzz_os::signal::Signal;
use disasm::RegisterOffset;
use log::*;
use std::collections::HashSet;
use std::ops::Range;

pub trait CfiTester {
    /// Invoked when the fuzzer wants to go to a new ICT. Returns whether the ICT should be tested.
    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)>;

    /// Returns whether the CFI system allows the target address.
    fn run_test(&mut self, target: u64) -> bool;

    /// Returns vmmap.
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap>;
}

pub struct LockdownTester {
    debugger: Debugger,

    addr_check: u64,
    addr_violation: u64,
    addr_rets: Vec<u64>,

    stack_backup: [u8; 0x20],
    /// Address of the parameter of target address sent to fbt_check_transfer.
    ptr_target: u64,
    /// Original target of jump.
    addr_target: u32,
    /// Backup of context.
    regs_backup: AMD64RegisterSet,
}

impl LockdownTester {
    fn disable_cache(debugger: &mut Debugger, elf: &Elf) {
        //   je +0x30; push rdx
        const PATCH_SRC: &[u8] = b"\x74\x2e\x52\x68";
        //   nop; nop; push rdx
        const PATCH_DST: &[u8] = b"\x90\x90\x52\x68";
        const OP_START: usize = 3;

        let (addr_fn, len) = elf.symbol_to_load("action_call_indirect");
        debug!("action_call_indirect at {:#x}, len = {}", addr_fn, len);
        let insns = debugger.disasm(&elf, addr_fn, len);
        let addr_patch = insns
            .iter()
            .find(|insn| insn.bytes().len() == 7 && &insn.bytes()[OP_START..] == PATCH_SRC)
            .expect("cannot locate signature of action_call_indirect")
            .address()
            + OP_START as u64;
        debug!("action_call_indirect: patch at {:#x}", addr_patch);
        debugger
            .process
            .trace_write_memory_force(addr_patch, PATCH_DST)
            .unwrap();
    }

    fn locate_fns(debugger: &mut Debugger, elf: &Elf) -> (u64, u64, Vec<u64>) {
        let sym = elf
            .symbol_by_filter(|name| name.starts_with("print_cftx"))
            .unwrap_or_else(|| panic!("cannot find print_cftx"));
        let addr_violation = elf.vma_to_load(sym.st_value);

        let (addr_fn, len) = elf.symbol_to_load("fbt_check_transfer");
        debug!("fbt_check_transfer at {:#x}, len = {}", addr_fn, len);
        let insns = debugger.disasm(&elf, addr_fn, len);
        let addr_rets: Vec<_> = insns
            .iter()
            .filter(|insn| insn.mnemonic().unwrap() == "ret")
            .map(|insn| insn.address())
            .collect();
        (addr_violation, addr_fn, addr_rets)
    }

    pub fn new(mut debugger: Debugger) -> Box<dyn CfiTester> {
        // We are at _start now.
        debugger.next_event().unwrap();
        let elf = Elf::from_process(debugger.process, None);

        let (addr_violation, addr_check, addr_rets) = Self::locate_fns(&mut debugger, &elf);
        debug!(
            "addr_violation = {:x}, addr_check = {:x}, addr_rets = {:x?}",
            addr_violation, addr_check, addr_rets
        );
        Self::disable_cache(&mut debugger, &elf);

        // Prepare for break! (but don't actually break at the moment)
        debugger.set_breakpoint(addr_violation);
        for &addr in &addr_rets {
            debugger.set_breakpoint(addr);
        }
        debugger.disable_breakpoints();

        Box::new(LockdownTester {
            debugger,
            addr_violation,
            addr_check,
            addr_rets,
            stack_backup: Default::default(),
            ptr_target: Default::default(),
            addr_target: Default::default(),
            regs_backup: Default::default(),
        })
    }
}

impl CfiTester for LockdownTester {
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap> {
        self.debugger.process.to_procfs().unwrap().maps().unwrap()
    }

    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)> {
        const OFFSET_TARGET: usize = 0xc;

        if self.addr_target != 0 {
            // Restore stack modified by last run.
            self.debugger.disable_breakpoints();
            self.debugger
                .process
                .trace_write_memory(self.regs_backup.rsp, &self.stack_backup)
                .unwrap();
            self.debugger
                .process
                .trace_write_memory(self.ptr_target, &self.addr_target.to_ne_bytes())
                .unwrap();
        }

        // Read target address by breakpoint (inserted by us).
        let regs = match self.debugger.next_event() {
            Ok(regs) => regs,
            Err(event) => {
                warn!("exiting with {:?}", event);
                return None;
            }
        };
        let current_ip = regs.rip as u32;

        // Run until fbt_check_transfer.
        let regs = self.debugger.run_until(&[self.addr_check]);
        assert!(
            regs.rip == self.addr_check,
            "mismatched check fn, rip = {:#x}",
            regs.rip
        );
        self.debugger.enable_breakpoints();

        // Read target address sent to fbt_check_transfer.
        self.debugger
            .process
            .trace_read_memory(regs.rsp, &mut self.stack_backup)
            .unwrap();
        let ptr_target = [
            self.stack_backup[OFFSET_TARGET],
            self.stack_backup[OFFSET_TARGET + 1],
            self.stack_backup[OFFSET_TARGET + 2],
            self.stack_backup[OFFSET_TARGET + 3],
        ];
        let ptr_target = u32::from_ne_bytes(ptr_target) as u64;
        let addr_target = self.debugger.read_u32(ptr_target);
        debug!("targets: {:x} => {:x}", ptr_target, addr_target);

        self.ptr_target = ptr_target;
        self.addr_target = addr_target;
        self.regs_backup = regs;
        return Some((format!("{:#x}", current_ip), self.debugger.vmmap('x')));
    }

    fn run_test(&mut self, target: u64) -> bool {
        let target = target as u32;

        // Set target address on stack.
        self.debugger
            .process
            .trace_write_memory(self.regs_backup.rsp, &self.stack_backup)
            .unwrap();
        self.debugger
            .process
            .trace_write_memory(self.ptr_target, &target.to_ne_bytes())
            .unwrap();

        // Read check result.
        let regs = self.debugger.next_event().unwrap();
        let jump_allowed = {
            let current_pc = regs.rip - 1;
            if current_pc == self.addr_violation {
                false
            } else if self.addr_rets.contains(&current_pc) {
                regs.rax != 0
            } else {
                unreachable!("unexpected check result, context = {:#x?}", regs)
            }
        };
        // Restore the registers.
        self.debugger.set_regs(&self.regs_backup);

        jump_allowed
    }
}

#[derive(Debug)]
pub struct LlvmTester {
    debugger: Debugger,
    regs_backup: AMD64RegisterSet,
    offset: RegisterOffset,
    addr_call: u64,
    elf: Option<Elf>,
}

impl LlvmTester {
    pub fn new(debugger: Debugger) -> Box<dyn CfiTester> {
        Box::new(LlvmTester {
            elf: None,
            debugger,
            regs_backup: Default::default(),
            offset: unsafe { field_offset::FieldOffset::new_from_offset(0) },
            addr_call: 0,
        })
    }

    fn maybe_update_elf(&mut self) {
        if self.elf.is_some() {
            return;
        }
        let cmdline = self
            .debugger
            .process
            .to_procfs()
            .unwrap()
            .cmdline()
            .unwrap();
        let real_binary = cmdline
            .iter()
            .find(|name| !name.ends_with(".so"))
            .expect("cannot find real binary");
        let real_binary = std::path::PathBuf::from(real_binary);
        let real_binary_name = real_binary.file_name().unwrap();
        debug!("real binary is {:?}", real_binary_name);

        self.elf = Some(Elf::from_process(
            self.debugger.process,
            Some(real_binary_name.as_ref()),
        ));
    }
}

impl CfiTester for LlvmTester {
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap> {
        self.debugger.process.to_procfs().unwrap().maps().unwrap()
    }

    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)> {
        if self.addr_call != 0 {
            self.debugger.remove_breakpoint(self.addr_call);
            self.debugger.set_regs(&self.regs_backup);
        }

        let (regs, insns, regid) = loop {
            let regs = match self.debugger.next_event() {
                Ok(regs) => regs,
                Err(event) => {
                    warn!("exiting with {:?}", event);
                    return None;
                }
            };
            let current_pc = regs.rip - 1;

            // Decode the target register and the next call using it.
            self.maybe_update_elf();
            let elf = self.elf.as_ref().unwrap();
            let insns = self.debugger.disasm_function(elf, current_pc);
            let insn = disasm::get_last_instruction(&insns, current_pc);
            let regid = disasm::get_regid_from_insn(&elf.disasm, insn);
            match regid {
                Ok(regid) => break (regs, insns, regid),
                Err(_) => warn!(
                    "cannot determine target register at {:#x} (vcall probably)",
                    current_pc
                ),
            }
        };

        let elf = self.elf.as_ref().unwrap();
        let addr_call = insns
            .iter()
            .find(|insn| {
                if insn.address() < regs.rip {
                    return false;
                }
                if let Some(insn_regid) = disasm::get_call_target(&elf.disasm, insn) {
                    if regid != insn_regid {
                        let expect = elf.disasm.reg_name(regid).unwrap();
                        let got = elf.disasm.reg_name(insn_regid).unwrap();
                        warn!(
                            "mismatched call target; maybe vtable (expect {}, got {})",
                            expect, got
                        );
                    }
                    true
                } else {
                    false
                }
            })
            .expect("cannot locate next call")
            .address();
        self.debugger.set_breakpoint(addr_call);
        debug!("addr_allow = {:#x}", addr_call);

        let offset = disasm::get_offset_from_regid(regid);
        let target = *offset.apply(&regs);
        let vmmap = self.debugger.process.to_procfs().unwrap().maps().unwrap();
        let perms = &vmmap
            .iter()
            .find(|segment| segment.address.0 <= target && segment.address.1 > target)
            .unwrap()
            .perms;
        let filter = if perms.contains('x') { 'x' } else { 'r' };
        debug!(
            "target = {:#x}, perms = {}, is_vtable = {}",
            target,
            perms,
            filter == 'r'
        );

        let search_space = vmmap
            .iter()
            .filter_map(|seg| {
                if !seg.perms.contains(filter) {
                    return None;
                }
                Some(seg.address.0..seg.address.1)
            })
            .collect();

        self.regs_backup = regs;
        self.offset = offset;
        self.addr_call = addr_call;
        Some((format!("{:#x}", self.regs_backup.rip), search_space))
    }

    fn run_test(&mut self, target: u64) -> bool {
        // Patch target register.
        let mut regs = self.regs_backup.clone();
        *self.offset.apply_mut(&mut regs) = target;
        self.debugger.set_regs(&regs);

        // Resume execution and check for result
        let r = self.debugger.next_event();
        match r {
            Ok(ref regs) if regs.rip - 1 == self.addr_call => true,
            Err(EventKind::Suspended(SuspendReason::Signal(Signal::SIGILL))) => false,
            _ => panic!("unexpected event: {:?}", r),
        }
    }
}

#[derive(Debug)]
pub struct TsxTester {
    debugger: Debugger,
    allowed: HashSet<u64>,
    seq_check: &'static [u8],
}

impl TsxTester {
    pub fn new(mut debugger: Debugger, seq_check: &'static [u8]) -> Box<dyn CfiTester> {
        debugger.next_event().unwrap();
        Box::new(Self {
            debugger,
            allowed: Default::default(),
            seq_check,
        })
    }

    pub fn new_rtm(debugger: Debugger) -> Box<dyn CfiTester> {
        const XEND: [u8; 3] = [0x0f, 0x01, 0xd5];
        Self::new(debugger, &XEND)
    }

    pub fn new_hle(debugger: Debugger) -> Box<dyn CfiTester> {
        const XRELEASE: [u8; 8] = [0x81, 0x6c, 0x24, 0xf8, 0x80, 0x80, 0x80, 0x80];
        Self::new(debugger, &XRELEASE)
    }
}

impl CfiTester for TsxTester {
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap> {
        self.debugger.process.to_procfs().unwrap().maps().unwrap()
    }

    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)> {
        let regs = match self.debugger.next_event() {
            Ok(regs) => regs,
            Err(event) => {
                warn!("exiting with {:?}", event);
                return None;
            }
        };
        let current_ip = regs.rip;

        self.allowed.clear();
        let vmmap = self.debugger.process.to_procfs().unwrap().maps().unwrap();
        for segment in &vmmap {
            if !segment.perms.contains('x') || !segment.perms.contains('r') {
                continue;
            }

            // Read the whole segment.
            let base = segment.address.0;
            let buf_len = segment.address.1 - base;
            let mut buf = Vec::with_capacity(buf_len as usize);
            unsafe { buf.set_len(buf_len as usize) };
            self.debugger
                .process
                .trace_read_memory(base, &mut buf[..])
                .unwrap();

            // Look for xend.
            let mut search_begin = 0;
            while let Some(offset) = buf[search_begin..]
                .iter()
                .position(|v| *v == self.seq_check[0])
            {
                let buf_offset = search_begin + offset;
                if &buf[buf_offset..buf_offset + self.seq_check.len()] == self.seq_check {
                    self.allowed.insert(base + buf_offset as u64);
                }
                search_begin += offset + 1;
            }
        }

        Some((format!("{:#x}", current_ip), self.debugger.vmmap('x')))
    }

    fn run_test(&mut self, target: u64) -> bool {
        self.allowed.contains(&target)
    }
}

#[derive(Debug)]
pub struct CfiLbTester {
    debugger: Debugger,
    elf: Elf,

    regs_backup: AMD64RegisterSet,
    offset: RegisterOffset,

    insn_allow: Vec<u64>,
    insn_deny: Vec<u64>,
}

impl CfiLbTester {
    // Adds locations of instructions reflecting CFI test result to the breakpoint list.
    // Pattern:
    //   any ret -> allow
    //   last nth call -> deny
    fn add_monitor_fns_by_symbol(
        &mut self,
        symbols: &'static [&'static str],
        deny_fn_rindex: usize,
    ) {
        for symbol in symbols {
            let (base, len) = self.elf.symbol_to_load(symbol);
            let mut rets = Vec::<u64>::new();
            let mut calls = Vec::<u64>::new();
            let insns = self.debugger.disasm(&self.elf, base, len);
            for insn in insns.iter() {
                match insn.mnemonic().unwrap() {
                    "ret" => rets.push(insn.address()),
                    "call" => calls.push(insn.address()),
                    _ => {}
                }
            }

            let deny_fn = calls[calls.len() - deny_fn_rindex];
            trace!(
                "signature of {} at {:#x}: allows = {:x?}, deny = {:x}",
                symbol,
                base,
                rets,
                deny_fn
            );
            self.insn_allow.extend(rets);
            self.insn_deny.push(deny_fn);
        }
    }

    fn break_monitor_fns(&mut self) {
        debug!("insn_allow: {:x?}", self.insn_allow);
        debug!("insn_deny: {:x?}", self.insn_deny);
        for &addr in self.insn_allow.iter().chain(self.insn_deny.iter()) {
            self.debugger.set_breakpoint(addr);
        }
    }

    fn create_partial(debugger: Debugger) -> Self {
        CfiLbTester {
            elf: Elf::from_process(debugger.process, None),
            debugger,

            regs_backup: Default::default(),
            offset: unsafe { field_offset::FieldOffset::new_from_offset(0) },

            insn_allow: Default::default(),
            insn_deny: Default::default(),
        }
    }

    pub fn new_cfilb(debugger: Debugger) -> Box<dyn CfiTester> {
        const CHECK_FNS: &[&str] = &[
            "cfilb_monitor_d0",
            "cfilb_monitor_d1",
            "cfilb_monitor_d2",
            "cfilb_monitor_d3",
        ];
        const FN_RINDEX: usize = 2;
        let mut this = Self::create_partial(debugger);
        this.add_monitor_fns_by_symbol(CHECK_FNS, FN_RINDEX);

        // This function doesn't work in fact.
        let (base, _len) = this.elf.symbol_to_load("cfilb_reference_monitor");
        debug!("cfilb_reference_monitor @ {:#x}", base);
        this.insn_allow.push(base);

        this.break_monitor_fns();
        Box::new(this)
    }

    pub fn new_oscfi(debugger: Debugger) -> Box<dyn CfiTester> {
        const CHECK_FNS: &[&str] = &[
            "static_vcall_reference_monitor",
            "oscfi_vcall_reference_monitor",
            "oscfi_pcall_reference_monitor",
            "oscfi_pcall_reference_monitor_d0",
            "oscfi_pcall_reference_monitor_d1",
            "oscfi_pcall_reference_monitor_d2",
            "oscfi_pcall_reference_monitor_d3",
        ];
        const FN_RINDEX: usize = 1;
        let mut this = Self::create_partial(debugger);
        this.add_monitor_fns_by_symbol(CHECK_FNS, FN_RINDEX);

        this.break_monitor_fns();
        Box::new(this)
    }
}

impl CfiTester for CfiLbTester {
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap> {
        self.debugger.process.to_procfs().unwrap().maps().unwrap()
    }

    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)> {
        if self.regs_backup.rip != 0 {
            // Restore traces of previous test.
            self.debugger.set_regs(&self.regs_backup);
        }

        self.debugger.disable_breakpoints();
        let regs = match self.debugger.next_event() {
            Ok(regs) => regs,
            Err(event) => {
                warn!("exiting with {:?}", event);
                return None;
            }
        };
        self.debugger.enable_breakpoints();

        let current_pc = regs.rip - 1;
        let mut stack = vec![current_pc];
        self.debugger.unwind_stack64(regs.rbp, 2, &mut stack);

        let insns = self.debugger.disasm_function(&self.elf, current_pc);
        let insn = disasm::get_last_instruction(&insns, current_pc);
        let regid = disasm::get_regid_from_insn(&self.elf.disasm, insn).unwrap();
        self.offset = disasm::get_offset_from_regid(regid);
        self.regs_backup = regs;

        Some((format!("{:x?}", stack), self.debugger.vmmap('x')))
    }

    fn run_test(&mut self, target: u64) -> bool {
        // Patch target register.
        let mut regs = self.regs_backup.clone();
        *self.offset.apply_mut(&mut regs) = target;
        self.debugger.set_regs(&regs);

        // Resume execution and check for result
        let regs = self.debugger.next_event().unwrap();
        let last_rip = regs.rip - 1;

        let allowed = self.insn_allow.contains(&last_rip);
        let denied = self.insn_deny.contains(&last_rip);
        match (allowed, denied) {
            (true, false) => true,
            (false, true) => false,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
pub struct MCfiTester {
    debugger: Debugger,
    elf: Elf,
    addr_report_fn: u64,
    addr_call: u64,
    addr_lock: u64,
    regs_backup: AMD64RegisterSet,
    offset: RegisterOffset,
}

impl MCfiTester {
    fn locate_report_fn(&self) -> u64 {
        const REPORT_FN_NAME: &str = "runtime_report_cfi_violation";
        let elf = Elf::from_process(self.debugger.process, Some("rock".to_owned().as_ref()));
        let (base, _len) = elf.symbol_to_load(REPORT_FN_NAME);
        debug!("report fn at {:#x}", base);
        base
    }

    fn search_buf(buf: &[u8], buf_start: u64, shadow_start: u64, ranges: &mut Vec<Range<u64>>) {
        assert!(buf.len() != 0 && buf.len() % 4096 == 0);
        let buf = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u64, buf.len() / 8) };
        assert!(buf.len() >= 512);

        for i in 0..buf.len() {
            // If qword@offset != 0, then it's possible that byte@offset and byte@offset+7 != 0.
            // If byte@offset != 0, then qword@offset-7 could be nonzero.
            // If byte@offset+7 != 0, then qword@offset+7 could be nonzero.
            // Summary: if byte@i != 0, then qword@[i-7..i+8) could be nonzero.
            if unsafe { *buf.get_unchecked(i) } != 0 {
                let addr_shadow = buf_start + i as u64 * 8;
                let addr = addr_shadow - shadow_start;
                let start = if addr >= 7 { addr - 7 } else { 0 };
                let end = addr + 8;
                if let Some(prev) = ranges.last_mut() {
                    // Merge last range if possible.
                    if prev.end >= start {
                        prev.end = end;
                        continue;
                    }
                }
                ranges.push(start..end);
            }
        }
    }

    fn search_table(&mut self, base: u64) -> Vec<Range<u64>> {
        const SEG_SIZE: usize = 0xfffef000;
        const PROT_NEW: i32 = dfuzz_os::libc::PROT_READ;
        const PROT_OLD: i32 = dfuzz_os::libc::PROT_WRITE;
        let mut r = vec![];

        // Enable reading with efficient process_vm_readv.
        self.debugger
            .mprotect(self.addr_report_fn, base, SEG_SIZE, PROT_NEW);

        // Search buffer of 64MiB each time.
        const CHUNK_SIZE: usize = 64 * 1024 * 1024;
        let mut buf = vec![0; CHUNK_SIZE];
        let mut begin = 0usize;
        loop {
            let end = usize::min(begin + CHUNK_SIZE, SEG_SIZE);
            let len = end - begin;
            if len == 0 {
                break;
            }

            // Read the buffer and find value.
            let buf = &mut buf[0..len];
            let buf_addr = base + begin as u64;
            self.debugger
                .process
                .trace_read_memory(buf_addr, buf)
                .unwrap();
            Self::search_buf(buf, buf_addr, base, &mut r);

            begin = end;
        }

        // Restore the protection.
        self.debugger
            .mprotect(self.addr_report_fn, base, SEG_SIZE, PROT_OLD);

        // Fixup ranges.
        if let Some(range) = r.last_mut() {
            let last = base + SEG_SIZE as u64;
            range.end = std::cmp::min(last, range.end);
        }

        // println!("ranges = {:#x?}", r);
        r
    }

    fn disable_protection(&mut self, addr: u64) {
        use dfuzz_os::libc;
        for range in self.debugger.vmmap('x') {
            if range.contains(&addr) {
                debug!(
                    "disable protection for {:#x}..{:#x}",
                    range.start, range.end
                );
                self.debugger.mprotect(
                    self.addr_report_fn,
                    range.start,
                    (range.end - range.start) as usize,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                );
            }
        }
    }

    pub fn new(debugger: Debugger) -> Box<dyn CfiTester> {
        Box::new(Self {
            elf: Elf::from_process(debugger.process, None),
            debugger,
            addr_report_fn: 0,
            addr_call: 0,
            addr_lock: 0,
            regs_backup: Default::default(),
            offset: unsafe { field_offset::FieldOffset::new_from_offset(0) },
        })
    }
}

impl CfiTester for MCfiTester {
    fn vmmap(&mut self) -> Vec<procfs::MemoryMap> {
        self.debugger.process.to_procfs().unwrap().maps().unwrap()
    }

    fn advance_ict(&mut self) -> Option<(String, Vec<Range<u64>>)> {
        if self.addr_call != 0 {
            self.debugger.remove_breakpoint(self.addr_call);
            self.debugger.remove_breakpoint(self.addr_lock);
            self.debugger.set_regs(&self.regs_backup);
        }

        let regs = match self.debugger.next_event() {
            Ok(regs) => regs,
            Err(event) => {
                warn!("exiting with {:?}", event);
                return None;
            }
        };

        if self.addr_report_fn == 0 {
            // First ICT.
            self.addr_report_fn = self.locate_report_fn();
            self.debugger.set_breakpoint(self.addr_report_fn);
            self.disable_protection(regs.rip);
            debug!("gs at {:#x}", regs.gs_base);
        }

        // Locate call, which denotes a passed check.
        let current_pc = regs.rip - 1;
        let (regid, addr_call, addr_lock) = {
            let insns = self.debugger.disasm_function(&self.elf, current_pc);
            let insns_after: Vec<_> = insns
                .iter()
                .skip_while(|insn| insn.address() != current_pc)
                .collect();
            let insn = disasm::get_last_instruction(&insns, current_pc);
            let regid = disasm::get_regid_from_insn(&self.elf.disasm, insn).unwrap();

            let insn_call = insns_after
                .iter()
                .find(|insn| insn.mnemonic() == Some("call"))
                .unwrap();
            // Locate jne, which deadlocks if the branch is taken.
            let insn_jne = insns_after
                .iter()
                .find(|insn| insn.mnemonic() == Some("jne"))
                .unwrap();
            let addr_lock = disasm::get_imm_from_insn(&self.elf.disasm, &insn_jne).unwrap();
            (regid, insn_call.address(), addr_lock)
        };

        let offset = disasm::get_offset_from_regid(regid);
        debug!(
            "breakpoint at {:#x} (pass) and {:#x} (lock), reg = {}",
            addr_call,
            addr_lock,
            self.elf.disasm.reg_name(regid).unwrap()
        );
        self.debugger.set_breakpoint(addr_call);
        self.debugger.set_breakpoint(addr_lock);

        self.offset = offset;
        self.addr_lock = addr_lock;
        self.addr_call = addr_call;
        self.regs_backup = regs;

        let ranges = self.search_table(self.regs_backup.gs_base);
        Some((format!("{:x?}", self.regs_backup.rip), ranges))
    }

    fn run_test(&mut self, target: u64) -> bool {
        let mut regs = self.regs_backup.clone();
        *self.offset.apply_mut(&mut regs) = target;
        self.debugger.set_regs(&regs);

        let regs = self.debugger.next_event().unwrap();
        let addr = regs.rip - 1;

        if addr == self.addr_call {
            true
        } else if addr == self.addr_report_fn {
            false
        } else if addr == self.addr_lock {
            let zf = regs.eflags & 0x40;
            if zf == 0 {
                // not equal => branch taken => deadlock
                warn!("deadlock detected, target = {:#x}", target);
                false
            } else {
                // branch not taken => report violation
                false
            }
        } else {
            unreachable!()
        }
    }
}
