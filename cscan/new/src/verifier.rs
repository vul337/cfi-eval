use super::binary::Elf;
use super::debugger::Debugger;
use super::disasm;
use super::range_set::RangeSet;
use dfuzz_os::arch::AMD64RegisterSet;
use humansize::{file_size_opts::BINARY, FileSize};
use log::*;
use std::time::Instant;

pub trait CfiVerifier {
    fn identify_ict(&mut self, _dbg: &mut Debugger, regs: &AMD64RegisterSet) -> String {
        format!("{:#x}", regs.rip)
    }

    fn verify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> RangeSet;
}

fn run_tests(targets: &RangeSet, mut f: impl FnMut(u64) -> bool) -> RangeSet {
    let mut total_runs = 0u32;
    let mut last_runs = 0u32;
    let mut started = Instant::now();
    let total_targets = targets.len();

    let mut allowed_targets = RangeSet::default();
    for target in targets.elements() {
        let jump_allowed = f(target);

        if jump_allowed {
            trace!(target: "run", "allowed target {:#x}", &target);
            allowed_targets.push(target);
        } else {
            trace!(target: "run", "denied target {:#x}", target);
        }

        total_runs += 1;
        last_runs += 1;
        if total_runs % 4096 == 0 {
            let duration = started.elapsed().as_secs_f64();
            if duration > 2.0 {
                let exec_per_sec = last_runs as f64 / duration;
                debug!(
                    "progress: {:.2}% ({} / {}), {}/s",
                    (total_runs as f64 / total_targets as f64 * 100.0),
                    allowed_targets.len(),
                    total_runs,
                    (exec_per_sec as u64).file_size(BINARY).unwrap(),
                );
                started = Instant::now();
                last_runs = 0;
            }
        }
    }

    debug!(
        "verification result: {} / {}",
        allowed_targets.len(),
        total_targets
    );
    allowed_targets
}

fn set_reg_by_offset(
    dbg: &mut Debugger,
    regs: &AMD64RegisterSet,
    offset: disasm::RegisterOffset,
    value: u64,
) {
    let mut regs = regs.clone();
    *offset.apply_mut(&mut regs) = value;
    dbg.set_regs(&regs);
}

pub struct CfiLbVerifier {
    elf: Elf,
    insn_allow: Vec<u64>,
    insn_deny: Vec<u64>,
    insn_skip: u64,
}

impl CfiLbVerifier {
    // Adds locations of instructions reflecting CFI test result to the breakpoint list.
    // Pattern:
    //   any ret -> allow
    //   last nth call -> deny
    fn add_monitor_fns_by_symbol(
        elf: &Elf,
        debugger: &mut Debugger,
        symbols: &[&str],
        deny_fn_rindex: usize,
    ) -> (Vec<u64>, Vec<u64>) {
        let mut insn_allow = vec![];
        let mut insn_deny = vec![];

        for symbol in symbols {
            let (base, len) = elf.symbol_to_load(symbol);
            let mut rets = Vec::<u64>::new();
            let mut calls = Vec::<u64>::new();
            let insns = debugger.disasm(&elf, base, len);
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
            insn_allow.extend(rets);
            insn_deny.push(deny_fn);
        }
        (insn_allow, insn_deny)
    }

    pub fn new(dbg: &mut Debugger) -> Self {
        const CHECK_FNS: &[&str] = &[
            "cfilb_monitor_d0",
            "cfilb_monitor_d1",
            "cfilb_monitor_d2",
            "cfilb_monitor_d3",
        ];
        const FN_RINDEX: usize = 2;

        let elf = Elf::from_process(dbg.process, None);
        let (mut insn_allow, insn_deny) =
            Self::add_monitor_fns_by_symbol(&elf, dbg, CHECK_FNS, FN_RINDEX);

        // This function doesn't work in fact.
        let (insn_skip, _) = elf.symbol_to_load("cfilb_reference_monitor");
        debug!("cfilb_reference_monitor @ {:#x}", insn_skip);
        insn_allow.push(insn_skip);

        insn_allow
            .iter()
            .chain(insn_deny.iter())
            .for_each(|&addr| dbg.set_breakpoint(addr));
        dbg.disable_breakpoints();
        Self {
            elf,
            insn_allow,
            insn_deny,
            insn_skip,
        }
    }
}

impl CfiVerifier for CfiLbVerifier {
    fn identify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> String {
        let mut stack = vec![regs.rip];
        dbg.unwind_stack64(regs.rbp, 2, &mut stack);
        format!("{:x?}", stack)
    }

    fn verify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> RangeSet {
        dbg.enable_breakpoints();

        // Identify insn_skip first.
        let targets = RangeSet::from_raw_ranges(dbg.vmmap('x'));
        let next_pc = dbg.next_event().unwrap().rip - 1;
        dbg.set_regs(regs);
        if next_pc == self.insn_skip {
            trace!("cfilb_reference_monitor reached, assuming this ICT accepts all targets");
            dbg.disable_breakpoints();
            return targets;
        }

        let pc = regs.rip - 1;
        let insns = dbg.disasm_function(&self.elf, pc);
        let insn = disasm::get_last_instruction(&insns, pc);
        let regid = disasm::get_regid_from_insn(&self.elf.disasm, insn).unwrap();
        let offset = disasm::get_offset_from_regid(regid);

        let r = run_tests(&targets, |addr| {
            set_reg_by_offset(dbg, regs, offset, addr);
            let pc = dbg.next_event().unwrap().rip - 1;
            let is_allowed = self.insn_allow.contains(&pc);
            let is_denied = self.insn_deny.contains(&pc);
            match (is_allowed, is_denied) {
                (true, false) => true,
                (false, true) => false,
                _ => unreachable!("unexpected rip at {:#x}", pc),
            }
        });

        dbg.disable_breakpoints();
        r
    }
}

pub struct MCfiVerifier {
    elf: Elf,
    addr_report_fn: u64,
}

impl MCfiVerifier {
    pub fn new(dbg: &mut Debugger) -> Self {
        Self {
            elf: Elf::from_process(dbg.process, None),
            addr_report_fn: 0,
        }
    }

    fn locate_report_fn(&self, dbg: &mut Debugger) -> u64 {
        const REPORT_FN_NAME: &str = "runtime_report_cfi_violation";
        let elf = Elf::from_process(dbg.process, Some("rock".to_owned().as_ref()));
        let (base, _len) = elf.symbol_to_load(REPORT_FN_NAME);
        debug!("report fn at {:#x}", base);
        base
    }

    fn disable_protection(&self, dbg: &mut Debugger, addr: u64) {
        use dfuzz_os::libc;
        for range in dbg.vmmap('x') {
            if range.contains(&addr) {
                debug!(
                    "disable protection for {:#x}..{:#x}",
                    range.start, range.end
                );
                dbg.mprotect(
                    self.addr_report_fn,
                    range.start,
                    (range.end - range.start) as usize,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                );
            }
        }
    }

    fn search_table(&mut self, dbg: &mut Debugger, base: u64) -> RangeSet {
        const SEG_SIZE: usize = 0xfffef000;
        const PROT_NEW: i32 = dfuzz_os::libc::PROT_READ;
        const PROT_OLD: i32 = dfuzz_os::libc::PROT_WRITE;
        let mut r = RangeSet::default();

        // Enable reading with efficient process_vm_readv.
        dbg.mprotect(self.addr_report_fn, base, SEG_SIZE, PROT_NEW);

        // Check the shadow value of an address.
        for segment in dbg.vmmap('x') {
            let seg_start = segment.start.min(SEG_SIZE as u64);
            let seg_end = segment.end.min(SEG_SIZE as u64);
            let len = (seg_end - seg_start) as usize;
            if len == 0 {
                continue;
            }

            let mut buf = vec![0; len];
            dbg.process
                .trace_read_memory(base + seg_start, &mut buf)
                .unwrap();
            for (pos, _) in buf.iter().enumerate().filter(|(_, v)| **v != 0) {
                r.push(seg_start + pos as u64);
            }
        }

        // Restore the protection.
        dbg.mprotect(self.addr_report_fn, base, SEG_SIZE, PROT_OLD);

        r
    }
}

impl CfiVerifier for MCfiVerifier {
    fn identify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> String {
        if self.addr_report_fn == 0 {
            // First ICT.
            self.addr_report_fn = self.locate_report_fn(dbg);
            dbg.set_breakpoint(self.addr_report_fn);
            self.disable_protection(dbg, regs.rip);
            debug!("gs at {:#x}", regs.gs_base);
        }
        format!("{:#x}", regs.rip)
    }

    fn verify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> RangeSet {
        // Locate call, which denotes a passed check.
        let pc = regs.rip - 1;
        let (regid, addr_call, addr_lock) = {
            let insns = dbg.disasm_function(&self.elf, pc);
            let insns_after: Vec<_> = insns
                .iter()
                .skip_while(|insn| insn.address() != pc)
                .collect();
            let insn = disasm::get_last_instruction(&insns, pc);
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
        dbg.set_breakpoint(addr_call);
        dbg.set_breakpoint(addr_lock);

        let targets = self.search_table(dbg, regs.gs_base);
        let r = run_tests(&targets, |addr| {
            set_reg_by_offset(dbg, regs, offset, addr);
            let pc = dbg.next_event().unwrap().rip - 1;

            if pc == self.addr_report_fn {
                false
            } else if pc == addr_call {
                true
            } else if pc == addr_lock {
                let zf = regs.eflags & 0x40;
                if zf == 0 {
                    // not equal => branch taken => deadlock
                    // warn!("deadlock detected, target = {:#x}", addr);
                    false
                } else {
                    // branch not taken => report violation
                    false
                }
            } else {
                unreachable!()
            }
        });

        dbg.remove_breakpoint(addr_call);
        dbg.remove_breakpoint(addr_lock);
        r
    }
}

pub struct LlvmVerifier {
    elf: Option<Elf>,
}

impl LlvmVerifier {
    pub fn new(_: &mut Debugger) -> Self {
        Self { elf: None }
    }

    fn maybe_update_elf(&mut self, dbg: &mut Debugger) {
        if self.elf.is_some() {
            return;
        }
        let cmdline = dbg.process.to_procfs().unwrap().cmdline().unwrap();
        let real_binary = cmdline
            .iter()
            .find(|name| !name.ends_with(".so"))
            .expect("cannot find real binary");
        let real_binary = std::path::PathBuf::from(real_binary);
        let real_binary_name = real_binary.file_name().unwrap();
        debug!("real binary is {:?}", real_binary_name);

        self.elf = Some(Elf::from_process(
            dbg.process,
            Some(real_binary_name.as_ref()),
        ));
    }
}

impl CfiVerifier for LlvmVerifier {
    fn verify_ict(&mut self, dbg: &mut Debugger, regs: &AMD64RegisterSet) -> RangeSet {
        self.maybe_update_elf(dbg);
        let elf = self.elf.as_ref().unwrap();

        // Same old boilerplate.
        let pc = regs.rip - 1;
        let insns = dbg.disasm_function(elf, pc);
        let insn = disasm::get_last_instruction(&insns, pc);
        let regid = disasm::get_regid_from_insn(&elf.disasm, insn).unwrap();
        let offset = disasm::get_offset_from_regid(regid);

        // Determine vcall or icall by finding the permission of the target segment.
        let target = *offset.apply(&regs);
        let vmmap = dbg.process.to_procfs().unwrap().maps().unwrap();
        let perms = &vmmap
            .iter()
            .find(|segment| segment.address.0 <= target && segment.address.1 > target)
            .unwrap()
            .perms;
        let is_vtable = !perms.contains('x');
        debug!(
            "target = {:#x}, perms = {}, is_vtable = {}",
            target, perms, is_vtable
        );

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
        debug!("addr_allow = {:#x}", addr_call);

        // Run tests.
        dbg.set_breakpoint(addr_call);
        let vmmap = dbg.vmmap(if is_vtable { 'r' } else { 'x' });
        let targets = RangeSet::from_raw_ranges(vmmap);
        let r = run_tests(&targets, |addr| {
            use dfuzz_os::process::*;
            use dfuzz_os::signal::*;
            set_reg_by_offset(dbg, regs, offset, addr);
            let event = dbg.next_event();
            match event {
                Ok(ref regs) if regs.rip - 1 == addr_call => true,
                Err(EventKind::Suspended(SuspendReason::Signal(Signal::SIGILL))) => false,
                _ => panic!("unexpected event: {:?}", event),
            }
        });
        dbg.remove_breakpoint(addr_call);
        r
    }
}
