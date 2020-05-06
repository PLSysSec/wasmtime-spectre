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
