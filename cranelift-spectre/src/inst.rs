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
        0 => &[0x89, 0xc0],
        1 => &[0x89, 0xc9],
        2 => &[0x89, 0xd2],
        3 => &[0x89, 0xdb],
        4 => &[0x89, 0xe4],
        5 => &[0x89, 0xed],
        6 => &[0x89, 0xf6],
        7 => &[0x89, 0xff],
        8 => &[0x45, 0x89, 0xc0],
        9 => &[0x45, 0x89, 0xc9],
        10 => &[0x45, 0x89, 0xd2],
        11 => &[0x45, 0x89, 0xdb],
        12 => &[0x45, 0x89, 0xe4],
        13 => &[0x45, 0x89, 0xed],
        14 => &[0x45, 0x89, 0xf6],
        15 => &[0x45, 0x89, 0xff],
        _ => panic!("Unknown reg"),
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
        0 => vec![0x48, 0x2d, 0xba],
        1 => vec![0x48, 0x81, 0xe9],
        2 => vec![0x48, 0x81, 0xea],
        3 => vec![0x48, 0x81, 0xeb],
        4 => vec![0x48, 0x81, 0xec],
        5 => vec![0x48, 0x81, 0xed],
        6 => vec![0x48, 0x81, 0xee],
        7 => vec![0x48, 0x81, 0xef],
        8 => vec![0x49, 0x81, 0xe8],
        9 => vec![0x49, 0x81, 0xe9],
        10 => vec![0x49, 0x81, 0xea],
        11 => vec![0x49, 0x81, 0xeb],
        12 => vec![0x49, 0x81, 0xec],
        13 => vec![0x49, 0x81, 0xed],
        14 => vec![0x49, 0x81, 0xee],
        15 => vec![0x49, 0x81, 0xef],
        _ => panic!("Unknown reg"),
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
        0 => &[0x48, 0x85, 0xc0],
        1 => &[0x48, 0x85, 0xc9],
        2 => &[0x48, 0x85, 0xd2],
        3 => &[0x48, 0x85, 0xdb],
        4 => &[0x48, 0x85, 0xe4],
        5 => &[0x48, 0x85, 0xed],
        6 => &[0x48, 0x85, 0xf6],
        7 => &[0x48, 0x85, 0xff],
        8 => &[0x4d, 0x85, 0xc0],
        9 => &[0x4d, 0x85, 0xc9],
        10 => &[0x4d, 0x85, 0xd2],
        11 => &[0x4d, 0x85, 0xdb],
        12 => &[0x4d, 0x85, 0xe4],
        13 => &[0x4d, 0x85, 0xed],
        14 => &[0x4d, 0x85, 0xf6],
        15 => &[0x4d, 0x85, 0xff],
        _ => panic!("Unknown reg"),
    }
}

// cmovz rax, r14
// cmovz rcx, r14
// cmovz rdx, r14
// cmovz rbx, r14
// cmovz rsp, r14
// cmovz rbp, r14
// cmovz rsi, r14
// cmovz rdi, r14
// cmovz r8, r14
// cmovz r9, r14
// cmovz r10, r14
// cmovz r11, r14
// cmovz r12, r14
// cmovz r13, r14
// cmovz r14, r14
// cmovz r15, r14
pub fn get_cmov_from_r14(reg: u16) -> &'static [u8] {
    match reg {
        0 => &[0x49, 0x0f, 0x44, 0xc6],
        1 => &[0x49, 0x0f, 0x44, 0xce],
        2 => &[0x49, 0x0f, 0x44, 0xd6],
        3 => &[0x49, 0x0f, 0x44, 0xde],
        4 => &[0x49, 0x0f, 0x44, 0xe6],
        5 => &[0x49, 0x0f, 0x44, 0xee],
        6 => &[0x49, 0x0f, 0x44, 0xf6],
        7 => &[0x49, 0x0f, 0x44, 0xfe],
        8 => &[0x4d, 0x0f, 0x44, 0xc6],
        9 => &[0x4d, 0x0f, 0x44, 0xce],
        10 => &[0x4d, 0x0f, 0x44, 0xd6],
        11 => &[0x4d, 0x0f, 0x44, 0xde],
        12 => &[0x4d, 0x0f, 0x44, 0xe6],
        13 => &[0x4d, 0x0f, 0x44, 0xee],
        14 => &[0x4d, 0x0f, 0x44, 0xf6],
        15 => &[0x4d, 0x0f, 0x44, 0xfe],
        _ => panic!("Unknown reg"),
    }
}

pub fn get_cfi_check_bytes(amt: u32) -> Vec<u8> {

    let b1 = get_sub_const_bytes(14, amt);
    let b2 = get_test_bytes(14);
    let b3 = get_cmov_from_r14(15);
    let b4 = get_cmov_from_r14(4);

    let mut ret = Vec::new();
    ret.extend_from_slice(&b1);
    ret.extend_from_slice(&b2);
    ret.extend_from_slice(&b3);
    ret.extend_from_slice(&b4);
    return ret;
}