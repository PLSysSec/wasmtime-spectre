pub fn get_lfence() -> &'static [u8] {
    &[0x0f, 0xae, 0xe8]
}

pub fn get_endbranch() -> &'static [u8] {
    &[0xf3, 0x0f, 0x1e, 0xfa]
}

//   41 5b                   pop    %r11
//   41 ff e3                jmpq   *%r11
pub fn get_pop_jump_ret() -> &'static [u8] {
    &[0x41, 0x5b, 0x41, 0xff, 0xe3]
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
        _ => panic!("Unknown reg:{}", reg),
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

// cmovz reg1, reg2
pub fn get_cmovz(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, true)
}

// cmovnz reg1, reg2
pub fn get_cmovnz(reg1: u16, reg2: u16) -> Vec<u8> {
    get_cmov(reg1, reg2, false)
}

/// `z`: if `true`, then generate a `cmovz` opcode;
/// else, generate a `cmovnz` opcode
fn get_cmov(reg1: u16, reg2: u16, z: bool) -> Vec<u8> {
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
    let byte3: u8 = if z { 0x44 } else { 0x45 };

    let reg_chooser: u8 = 0b11000000;
    let reg1_choose: u8 = get_reg_bits(reg1);
    let reg2_choose: u8 = get_reg_bits(reg2);
    let byte4 = reg_chooser | (reg1_choose << 3) | reg2_choose;

    return vec![byte1, byte2, byte3, byte4];
}

/// `label`: CFI label to compare against
/// `zero_r15`: whether to zero `r15` if the CFI label is wrong
/// `zero_rsp`: whether to zero `rsp` if the CFI label is wrong
pub fn get_cfi_check_bytes(label: u64, zero_r15: bool, zero_rsp: bool) -> Vec<u8> {
    if !zero_r15 && !zero_rsp {
        // if we're not zeroing anything, we don't even need to check the label
        return Vec::new();
    }

    // we are using 32-bit labels for now
    let label = label as u32;

    let mut bytes = get_sub_const_bytes(R_R14, label);
    bytes.extend_from_slice(get_test_bytes(R_R14));
    if zero_r15 {
        bytes.extend_from_slice(&get_cmovnz(R_R15, R_R14));
    }
    if zero_rsp {
        bytes.extend_from_slice(&get_cmovnz(R_RSP, R_R14));
    }

    return bytes;
}

pub fn get_condbr_new_cfi_label_bytes(
    block1_label_reg: u16,
    block2_label_reg: u16,
    out_reg: u16,
) -> Vec<u8> {
    // See docs on the "condbr_get_new_cfi_label" instruction
    // (notes in meta/src/isa/x86/instructions.rs)
    // This should return the bytes for the following instructions:
    // ```
    // test r14, r14
    // cmovz r14, block1_label
    // mov out, r14
    // cmovz out, block2_label
    // ```

    let mut bytes = get_test_bytes(R_R14).to_vec();
    bytes.extend_from_slice(&get_cmovz(R_R14, block1_label_reg));
    bytes.extend_from_slice(get_mov_from_r14(out_reg));
    bytes.extend_from_slice(&get_cmovz(out_reg, block2_label_reg));
    bytes
}

// pub fn get_uncondbr_new_cfi_label_bytes(block1_label_reg: u16) -> Vec<u8> {
//     // mov out, block1_label
//     let mut bytes = get_test_bytes(R_R14).to_vec();
//     bytes.extend_from_slice(&get_cmovz(R_R14, block1_label_reg));
//     bytes
// }
