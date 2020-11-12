use std::mem::transmute;

#[repr(C)]
#[derive(Clone, Default, Eq, PartialEq, Hash, Debug)]
pub struct AMD64RegisterSet {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

pub const AMD64_REGISTER_NAMES: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];

impl Into<[u64; 27]> for AMD64RegisterSet {
    fn into(self) -> [u64; 27] {
        unsafe { transmute(self) }
    }
}

impl From<[u64; 27]> for AMD64RegisterSet {
    fn from(array: [u64; 27]) -> Self {
        unsafe { transmute(array) }
    }
}
