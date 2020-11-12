use super::debugger::Debugger;
use dfuzz_os::arch::AMD64RegisterSet;

pub trait CfiVerifier {
    fn on_entry(dbg: &mut Debugger, regs: AMD64RegisterSet) -> Self;
    fn on_first_ict(_dbg: &mut Debugger) {}

    fn get_ict_id(&mut self, dbg: &mut Debugger) -> String;
    fn run_tests(&mut self, dbg: &mut Debugger);
}
// struct LockdownTester {}

// impl CfiVerifier for LockdownTester {
//     fn on_entry(dbg: &mut Debugger, regs: AMD64RegisterSet) -> Self {
//         let t = Self::on_entry(dbg, regs);
//     }
// }
