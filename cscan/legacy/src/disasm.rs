use capstone::arch::x86::X86OperandType;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use dfuzz_os::arch::AMD64RegisterSet;
use field_offset::{offset_of, FieldOffset};

pub type RegisterOffset = FieldOffset<AMD64RegisterSet, u64>;

pub fn get_offset_from_regid(regid: RegId) -> RegisterOffset {
    use capstone::arch::x86::X86Reg::*;
    match regid.0 as u32 {
        X86_REG_R8 | X86_REG_R8D | X86_REG_R8W | X86_REG_R8B => offset_of!(AMD64RegisterSet => r8),
        X86_REG_R9 | X86_REG_R9D | X86_REG_R9W | X86_REG_R9B => offset_of!(AMD64RegisterSet => r9),
        X86_REG_R10 | X86_REG_R10D | X86_REG_R10W | X86_REG_R10B => offset_of!(AMD64RegisterSet => r10),
        X86_REG_R11 | X86_REG_R11D | X86_REG_R11W | X86_REG_R11B => offset_of!(AMD64RegisterSet => r11),
        X86_REG_R12 | X86_REG_R12D | X86_REG_R12W | X86_REG_R12B => offset_of!(AMD64RegisterSet => r12),
        X86_REG_R13 | X86_REG_R13D | X86_REG_R13W | X86_REG_R13B => offset_of!(AMD64RegisterSet => r13),
        X86_REG_R14 | X86_REG_R14D | X86_REG_R14W | X86_REG_R14B => offset_of!(AMD64RegisterSet => r14),
        X86_REG_R15 | X86_REG_R15D | X86_REG_R15W | X86_REG_R15B => offset_of!(AMD64RegisterSet => r15),
        X86_REG_AL | X86_REG_AH | X86_REG_AX | X86_REG_EAX | X86_REG_RAX => offset_of!(AMD64RegisterSet => rax),
        X86_REG_BL | X86_REG_BH | X86_REG_BX | X86_REG_EBX | X86_REG_RBX => offset_of!(AMD64RegisterSet => rbx),
        X86_REG_CL | X86_REG_CH | X86_REG_CX | X86_REG_ECX | X86_REG_RCX => offset_of!(AMD64RegisterSet => rcx),
        X86_REG_DL | X86_REG_DH | X86_REG_DX | X86_REG_EDX | X86_REG_RDX => offset_of!(AMD64RegisterSet => rdx),
        X86_REG_SI | X86_REG_ESI | X86_REG_RSI => offset_of!(AMD64RegisterSet => rsi),
        X86_REG_DI | X86_REG_EDI | X86_REG_RDI => offset_of!(AMD64RegisterSet => rdi),
        X86_REG_BP | X86_REG_EBP | X86_REG_RBP => offset_of!(AMD64RegisterSet => rbp),
        X86_REG_SP | X86_REG_ESP | X86_REG_RSP => offset_of!(AMD64RegisterSet => rsp),
        _ => panic!("unrecognized register {:?}", regid),
    }
}

pub fn get_last_instruction<'a>(
    insns: &'a capstone::Instructions,
    current_pc: u64,
) -> capstone::Insn<'a> {
    let mut last = None;
    for insn in insns.iter() {
        if insn.address() == current_pc {
            return last.expect("current pc is at the beginning");
        }
        last = Some(insn);
    }
    last.expect("cannot locate last instruction")
}

pub fn get_imm_from_insn(cs: &Capstone, insn: &capstone::Insn) -> Result<u64, ()> {
    let detail = cs.insn_detail(&insn).unwrap();
    let operands = detail.arch_detail().operands();
    for operand in operands {
        if let ArchOperand::X86Operand(operand) = operand {
            if let X86OperandType::Imm(imm) = operand.op_type {
                return Ok(imm as _);
            }
        } else {
            panic!("non x86 operand");
        }
    }
    Err(())
}

pub fn get_regid_from_insn(cs: &Capstone, insn: capstone::Insn) -> Result<RegId, &'static str> {
    log::trace!("identifying regid for {}", insn);

    if insn.mnemonic().unwrap() != "mov" {
        return Err("operand mismatch");
    }

    let detail = cs.insn_detail(&insn).unwrap();
    let operands = detail.arch_detail().operands();
    let mut regid = None;
    for operand in operands {
        if let ArchOperand::X86Operand(operand) = operand {
            if let X86OperandType::Reg(reg) = operand.op_type {
                if let Some(access) = operand.access {
                    if access.is_writable() && regid.is_none() {
                        regid = Some(reg)
                    } else {
                        return Err("multiple writes");
                    }
                }
            }
        } else {
            panic!("non x86 operand");
        }
    }

    regid.ok_or("written register not found")
}

pub fn get_call_target(capstone: &Capstone, insn: &capstone::Insn) -> Option<RegId> {
    if insn.mnemonic().unwrap() != "call" {
        return None;
    }

    let detail = capstone.insn_detail(&insn).unwrap();
    let operands = detail.arch_detail().operands();
    let operand = &operands[0];
    if let ArchOperand::X86Operand(operand) = operand {
        match operand.op_type {
            X86OperandType::Reg(reg) => return Some(reg),
            X86OperandType::Mem(mem) => return Some(mem.base()),
            _ => {}
        }
    }

    return None;
}
