use std::cell::RefCell;

pub const DEBUG_MODE: bool = false;
pub const IGNORE_TRAPS_IN: &'static str = "dlmalloc";

pub fn get_lfence() -> &'static [u8] {
    &[0x0f, 0xae, 0xe8]
}

pub fn get_endbranch() -> &'static [u8] {
    &[0xf3, 0x0f, 0x1e, 0xfa]
}

pub const R_RAX: u16 = 16;
pub const R_RCX: u16 = 17;
pub const R_RDX: u16 = 18;
pub const R_RBX: u16 = 19;
pub const R_RSP: u16 = 20;
pub const R_RBP: u16 = 21;
pub const R_RSI: u16 = 22;
pub const R_RDI: u16 = 23;
pub const R_R8 : u16 = 24;
pub const R_R9 : u16 = 25;
pub const R_R10: u16 = 26;
pub const R_R11: u16 = 27;
pub const R_R12: u16 = 28;
pub const R_R13: u16 = 29;
pub const R_R14: u16 = 30;
pub const R_R15: u16 = 31;

// mov eax, eax
// mov ecx, ecx
// mov edx, edx
// mov ebx, ebx
// mov esp, esp
// mov ebp, ebp
// mov esi, esi
// mov edi, edi
// mov r8d, r8d
// mov r9d, r9d
// mov r10d, r10d
// mov r11d, r11d
// mov r12d, r12d
// mov r13d, r13d
// mov r14d, r14d
// mov r15d, r15d
pub fn get_reg_truncate_bytes(reg: u16) -> &'static [u8] {
    match reg {
        R_RAX => &[0x89, 0xc0],
        R_RCX => &[0x89, 0xc9],
        R_RDX => &[0x89, 0xd2],
        R_RBX => &[0x89, 0xdb],
        R_RSP => &[0x89, 0xe4],
        R_RBP => &[0x89, 0xed],
        R_RSI => &[0x89, 0xf6],
        R_RDI => &[0x89, 0xff],
        R_R8  => &[0x45, 0x89, 0xc0],
        R_R9  => &[0x45, 0x89, 0xc9],
        R_R10 => &[0x45, 0x89, 0xd2],
        R_R11 => &[0x45, 0x89, 0xdb],
        R_R12 => &[0x45, 0x89, 0xe4],
        R_R13 => &[0x45, 0x89, 0xed],
        R_R14 => &[0x45, 0x89, 0xf6],
        R_R15 => &[0x45, 0x89, 0xff],
        _ => panic!("Unknown reg:{}", reg),
    }
}

// sub rax, const
// sub rcx, const
// sub rdx, const
// sub rbx, const
// sub rsp, const
// sub rbp, const
// sub rsi, const
// sub rdi, const
// sub r8, const
// sub r9, const
// sub r10, const
// sub r11, const
// sub r12, const
// sub r13, const
// sub r14, const
// sub r15, const
pub fn get_sub_const_bytes(reg: u16, amt: u32) -> Vec<u8> {
    let mut bytes = match reg {
        R_RAX => vec![0x48, 0x2d, 0xba],
        R_RCX => vec![0x48, 0x81, 0xe9],
        R_RDX => vec![0x48, 0x81, 0xea],
        R_RBX => vec![0x48, 0x81, 0xeb],
        R_RSP => vec![0x48, 0x81, 0xec],
        R_RBP => vec![0x48, 0x81, 0xed],
        R_RSI => vec![0x48, 0x81, 0xee],
        R_RDI => vec![0x48, 0x81, 0xef],
        R_R8  => vec![0x49, 0x81, 0xe8],
        R_R9  => vec![0x49, 0x81, 0xe9],
        R_R10 => vec![0x49, 0x81, 0xea],
        R_R11 => vec![0x49, 0x81, 0xeb],
        R_R12 => vec![0x49, 0x81, 0xec],
        R_R13 => vec![0x49, 0x81, 0xed],
        R_R14 => vec![0x49, 0x81, 0xee],
        R_R15 => vec![0x49, 0x81, 0xef],
        _ => panic!("Unknown reg:{}", reg),
    };

    let amt_bytes: [u8; 4] = unsafe { std::mem::transmute(amt.to_le()) };
    amt_bytes.iter().for_each(|b| bytes.push(*b));
    return bytes;
}

// sub destreg, srcreg
// 64-bit subtraction
pub fn get_sub_bytes(destreg: u16, srcreg: u16) -> Vec<u8> {
    let rexw = 0x48;
    let reg1_bit = if srcreg > R_RDI { 0b100 } else { 0 };
    let reg2_bit = if destreg > R_RDI { 0b001 } else { 0 };
    let rexw = rexw | reg1_bit | reg2_bit;

    let modrm_mod: u8 = 0b11000000;
    let modrm_reg: u8 = get_reg_bits(srcreg);
    let modrm_rm: u8 = get_reg_bits(destreg);
    let modrm = modrm_mod | (modrm_reg << 3) | modrm_rm;

    vec![ rexw, 0x29, modrm ]
}

// test rax, rax
// test rcx, rcx
// test rdx, rdx
// test rbx, rbx
// test rsp, rsp
// test rbp, rbp
// test rsi, rsi
// test rdi, rdi
// test r8, r8
// test r9, r9
// test r10, r10
// test r11, r11
// test r12, r12
// test r13, r13
// test r14, r14
// test r15, r15
pub fn get_test_bytes(reg: u16) -> &'static [u8] {
    match reg {
        R_RAX => &[0x48, 0x85, 0xc0],
        R_RCX => &[0x48, 0x85, 0xc9],
        R_RDX => &[0x48, 0x85, 0xd2],
        R_RBX => &[0x48, 0x85, 0xdb],
        R_RSP => &[0x48, 0x85, 0xe4],
        R_RBP => &[0x48, 0x85, 0xed],
        R_RSI => &[0x48, 0x85, 0xf6],
        R_RDI => &[0x48, 0x85, 0xff],
        R_R8  => &[0x4d, 0x85, 0xc0],
        R_R9  => &[0x4d, 0x85, 0xc9],
        R_R10 => &[0x4d, 0x85, 0xd2],
        R_R11 => &[0x4d, 0x85, 0xdb],
        R_R12 => &[0x4d, 0x85, 0xe4],
        R_R13 => &[0x4d, 0x85, 0xed],
        R_R14 => &[0x4d, 0x85, 0xf6],
        R_R15 => &[0x4d, 0x85, 0xff],
        _ => panic!("Unknown reg:{}", reg),
    }
}

/// zero target reg, padded to 3 bytes
// xor eax, eax
// xor ecx, ecx
// xor edx, edx
// xor ebx, ebx
// xor esp, esp
// xor ebp, ebp
// xor esi, esi
// xor edi, edi
// xor r8d, r8d
// xor r9d, r9d
// xor r10d, r10d
// xor r11d, r11d
// xor r12d, r12d
// xor r13d, r13d
// xor r14d, r14d
// xor r15d, r15d
pub fn get_zero_bytes(reg: u16) -> &'static [u8] {
    match reg {
        R_RAX => &[0x90, 0x31, 0xc0],
        R_RCX => &[0x90, 0x31, 0xc9],
        R_RDX => &[0x90, 0x31, 0xd2],
        R_RBX => &[0x90, 0x31, 0xdb],
        R_RSP => &[0x90, 0x31, 0xe4],
        R_RBP => &[0x90, 0x31, 0xed],
        R_RSI => &[0x90, 0x31, 0xf6],
        R_RDI => &[0x90, 0x31, 0xff],
        R_R8  => &[0x45, 0x31, 0xc0],
        R_R9  => &[0x45, 0x31, 0xc9],
        R_R10 => &[0x45, 0x31, 0xd2],
        R_R11 => &[0x45, 0x31, 0xdb],
        R_R12 => &[0x45, 0x31, 0xe4],
        R_R13 => &[0x45, 0x31, 0xed],
        R_R14 => &[0x45, 0x31, 0xf6],
        R_R15 => &[0x45, 0x31, 0xff],
        _ => panic!("Unknown reg:{}", reg),
    }
}

fn get_reg_bits(reg: u16) -> u8 {
    match reg {
        R_RAX => 0,
        R_RCX => 1,
        R_RDX => 2,
        R_RBX => 3,
        R_RSP => 4,
        R_RBP => 5,
        R_RSI => 6,
        R_RDI => 7,
        R_R8  => 0,
        R_R9  => 1,
        R_R10 => 2,
        R_R11 => 3,
        R_R12 => 4,
        R_R13 => 5,
        R_R14 => 6,
        R_R15 => 7,
        _ => panic!("Unknown reg: {}", reg),
    }
}

// mov rax, r14
// mov rcx, r14
// mov rdx, r14
// mov rbx, r14
// mov rsp, r14
// mov rbp, r14
// mov rsi, r14
// mov rdi, r14
// mov r8, r14
// mov r9, r14
// mov r10, r14
// mov r11, r14
// mov r12, r14
// mov r13, r14
// mov r14, r14
// mov r15, r14
pub fn get_mov_from_r14(reg: u16) -> &'static [u8] {
    match reg {
        R_RAX => &[0x4c, 0x89, 0xf0],
        R_RCX => &[0x4c, 0x89, 0xf1],
        R_RDX => &[0x4c, 0x89, 0xf2],
        R_RBX => &[0x4c, 0x89, 0xf3],
        R_RSP => &[0x4c, 0x89, 0xf4],
        R_RBP => &[0x4c, 0x89, 0xf5],
        R_RSI => &[0x4c, 0x89, 0xf6],
        R_RDI => &[0x4c, 0x89, 0xf7],
        R_R8  => &[0x4d, 0x89, 0xf0],
        R_R9  => &[0x4d, 0x89, 0xf1],
        R_R10 => &[0x4d, 0x89, 0xf2],
        R_R11 => &[0x4d, 0x89, 0xf3],
        R_R12 => &[0x4d, 0x89, 0xf4],
        R_R13 => &[0x4d, 0x89, 0xf5],
        R_R14 => &[0x4d, 0x89, 0xf6],
        R_R15 => &[0x4d, 0x89, 0xf7],
        _ => panic!("Unknown reg:{}", reg),
    }
}

// mov r14, imm
pub fn get_movimm_to_r14(imm: u64) -> Vec<u8> {
    let mut bytes = vec![0x49, 0xbe];
    let amt_bytes: [u8; 8] = unsafe { std::mem::transmute(imm.to_le()) };
    amt_bytes.iter().for_each(|b| bytes.push(*b));
    return bytes;
}

pub fn get_cmova(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x47)
}
pub fn get_cmovae(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x43)
}
pub fn get_cmovb(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x42)
}
pub fn get_cmovbe(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x46)
}
pub fn get_cmovc(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x42)
}
pub fn get_cmove(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x44)
}
pub fn get_cmovg(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4f)
}
pub fn get_cmovge(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4d)
}
pub fn get_cmovl(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4c)
}
pub fn get_cmovle(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4e)
}
pub fn get_cmovna(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x46)
}
pub fn get_cmovnae(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x42)
}
pub fn get_cmovnb(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x43)
}
pub fn get_cmovnbe(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x47)
}
pub fn get_cmovnc(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x43)
}
pub fn get_cmovne(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x45)
}
pub fn get_cmovng(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4e)
}
pub fn get_cmovnge(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4c)
}
pub fn get_cmovnl(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4d)
}
pub fn get_cmovnle(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4f)
}
pub fn get_cmovno(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x41)
}
pub fn get_cmovnp(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4b)
}
pub fn get_cmovns(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x49)
}
pub fn get_cmovnz(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x45)
}
pub fn get_cmovo(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x40)
}
pub fn get_cmovp(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4a)
}
pub fn get_cmovpe(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4a)
}
pub fn get_cmovpo(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x4b)
}
pub fn get_cmovs(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x48)
}
pub fn get_cmovz(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, 0x44)
}

/// opbyte specifies the byte that controls the condition op
fn get_cmov(reg1: u16, reg2: u16, opbyte: u8) -> Vec<u8> {
    // cmovz:
    // REX.W + 0F 44 /r
    // cmovnz:
    // REX.W + 0F 45 /r
    //
    // where REX.W is 0x4 (1(0|1)0(0|1))

    let rexw: u8 = 0x48;
    let reg1_bit = if reg1 > R_RDI { 0b100 } else { 0 };
    let reg2_bit = if reg2 > R_RDI { 0b001 } else { 0 };

    let byte1 = rexw | reg1_bit | reg2_bit;
    let byte2: u8 = 0x0f;
    let byte3: u8 = opbyte;

    let modrm_mod: u8 = 0b11000000;
    let modrm_reg: u8 = get_reg_bits(reg1);
    let modrm_rm: u8 = get_reg_bits(reg2);
    let byte4 = modrm_mod | (modrm_reg << 3) | modrm_rm;

    return vec![byte1, byte2, byte3, byte4];
}

thread_local! {
    static CURR_COMPILER_FUNC: RefCell<String> = RefCell::new(String::new());
}

pub fn set_curr_func(s: String) {
    CURR_COMPILER_FUNC.with(|curr| {
        *curr.borrow_mut() = s;
    });
}

pub fn get_curr_func() -> String {
    CURR_COMPILER_FUNC.with(|curr| {
        let ret = &*curr.borrow();
        return ret.clone();
    })
}

pub fn get_condbr_new_cfi_label_bytes(
    block_label_reg: u16,
    out_reg: u16,
) -> Vec<u8> {
    // See docs on the "condbr_get_new_cfi_label" instruction
    // in the form in which it existed prior to wasmtime commit
    // cd418822.
    // (notes in meta/src/isa/x86/instructions.rs)
    //
    // This should return the bytes for the following instructions:
    // ```
    // mov out, r14
    // cmovz out, block2_label
    // ```

    let mut bytes = get_mov_from_r14(out_reg).to_vec();
    bytes.extend_from_slice(&get_cmovz(out_reg, block_label_reg));
    bytes
}

// ; curr_top = *top_ptr
// mov RA, [r15 - 4096 - 32]
// ; curr_top-=8
// sub RA, 8
// ; *top_ptr = curr_top
// mov [r15 - 4096 - 32], RA
// ; target = call + 5
// lea RB, [rel target]
// ; *curr_top = target
// mov [RA], RB
// target:
//
// 3 versions
// RA=rax, RB=r11
// RA=rax, RB=r10
// RA=r10, RB=r11
pub fn get_shadow_stack_call_guard_bytes(call_size: u8, call_reg: Vec<u16>) -> Vec<u8> {
    let mov_inst_size: u8 = 0x3;
    let rax_r11_version = vec![
        0x49, 0x8b, 0x87, 0xe0, 0xef, 0xff, 0xff,
        0x48, 0x83, 0xe8, 0x08,
        0x49, 0x89, 0x87, 0xe0, 0xef, 0xff, 0xff,
        0x4c, 0x8d, 0x1d, mov_inst_size + call_size, 0x00, 0x00, 0x00,
        0x4c, 0x89, 0x18
    ];
    let rax_r10_version = vec![
        0x49, 0x8b, 0x87, 0xe0, 0xef, 0xff, 0xff,
        0x48, 0x83, 0xe8, 0x08,
        0x49, 0x89, 0x87, 0xe0, 0xef, 0xff, 0xff,
        0x4c, 0x8d, 0x15, 0x08, 0x00, 0x00, 0x00,
        0x4c, 0x89, 0x10,
    ];
    let r10_r11_version = vec![
        0x4d, 0x8b, 0x97, 0xe0, 0xef, 0xff, 0xff,
        0x49, 0x83, 0xea, 0x08,
        0x4d, 0x89, 0x97, 0xe0, 0xef, 0xff, 0xff,
        0x4c, 0x8d, 0x1d, mov_inst_size + call_size, 0x00, 0x00, 0x00,
        0x4d, 0x89, 0x1a,
    ];
    let ret =
        if call_reg.contains(&R_R10) {
            assert!(!call_reg.contains(&R_RAX));
            assert!(!call_reg.contains(&R_R11));
            rax_r11_version
        } else if call_reg.contains(&R_R11) {
            assert!(!call_reg.contains(&R_RAX));
            assert!(!call_reg.contains(&R_R10));
            rax_r10_version
        } else {
            assert!(!call_reg.contains(&R_R10));
            assert!(!call_reg.contains(&R_R11));
            r10_r11_version
        };
    return ret;
}

// ; curr_top = *top_ptr
// mov r9, [r15 - 4096 - 32]
// ; curr_top+=8
// add r9, 8
// ; *top_ptr = curr_top
// mov [r15 - 4096 - 32], r9
pub fn get_shadow_stack_postcall_guard_bytes() -> &'static [u8] {
    &[
        0x4d, 0x8b, 0x8f, 0xe0, 0xef, 0xff, 0xff,
        0x49, 0x83, 0xc1, 0x08,
        0x4d, 0x89, 0x8f, 0xe0, 0xef, 0xff, 0xff,
    ]
}

// mov r11, [r15 - 4096 - 32]
// pop r9
// jmp [r11]
pub fn get_pop_jump_ret() -> &'static [u8] {
    &[
        0x4d, 0x8b, 0x9f, 0xe0, 0xef, 0xff, 0xff,
        0x41, 0x59,
        0x41, 0xff, 0x23
    ]
}
