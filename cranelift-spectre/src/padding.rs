// https://github.com/shravanrn/nacl-llvm/blob/e03a22c37de3fe46798b5217b2b9e7dcc5d0c15b/test/MC/MachO/x86_32-optimal_nop.s
// # 1 byte nop test
//         # nop
//         # 0x90
// # 2 byte nop test
//         # xchg %ax,%ax
//         # 0x66, 0x90
// # 3 byte nop test
//         # nopl (%[re]ax)
//         # 0x0f, 0x1f, 0x00
// # 4 byte nop test
//         # nopl 0(%[re]ax)
//         # 0x0f, 0x1f, 0x40, 0x00
// # 5 byte nop test
//         # nopl 0(%[re]ax,%[re]ax,1)
//         # 0x0f, 0x1f, 0x44, 0x00, 0x00
// # 6 byte nop test
//         # nopw 0(%[re]ax,%[re]ax,1)
//         # 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00
// # 7 byte nop test
//         # nopl 0L(%[re]ax)
//         # 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00
// # 8 byte nop test
//         # nopl 0L(%[re]ax,%[re]ax,1)
//         # 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
// # 9 byte nop test
//         # nopw 0L(%[re]ax,%[re]ax,1)
//         # 0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
// # 10 byte nop test
//         # nopw %cs:0L(%[re]ax,%[re]ax,1)
//         # 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
// # 11 byte nop test
//         # nopw %cs:0L(%[re]ax,%[re]ax,1)
//         # 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00
// # 12 byte nop test
//         # nopw 0(%[re]ax,%[re]ax,1)
//         # nopw 0(%[re]ax,%[re]ax,1)
//         # 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
//         # 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00
// # 13 byte nop test
//         # nopw 0(%[re]ax,%[re]ax,1)
//         # nopl 0L(%[re]ax)
//         # 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
//         # 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00
// # 14 byte nop test
//         # nopl 0L(%[re]ax)
//         # nopl 0L(%[re]ax)
//         # 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
//         # 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00
// # 15 byte nop test
//         # nopl 0L(%[re]ax)
//         # nopl 0L(%[re]ax,%[re]ax,1)
//         # 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
//         # 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00

// https://github.com/shravanrn/nacl-llvm/blob/e03a22c37de3fe46798b5217b2b9e7dcc5d0c15b/lib/Target/X86/X86MCInstLower.cpp
// while (NumBytes) {
//     unsigned Opc, BaseReg, ScaleVal, IndexReg, Displacement, SegmentReg;
//     Opc = IndexReg = Displacement = SegmentReg = 0;
//     BaseReg = X86::RAX; ScaleVal = 1;
//     switch (NumBytes) {
//     case  0: llvm_unreachable("Zero nops?"); break;
//     case  1: NumBytes -=  1; Opc = X86::NOOP; break;
//     case  2: NumBytes -=  2; Opc = X86::XCHG16ar; break;
//     case  3: NumBytes -=  3; Opc = X86::NOOPL; break;
//     case  4: NumBytes -=  4; Opc = X86::NOOPL; Displacement = 8; break;
//     case  5: NumBytes -=  5; Opc = X86::NOOPL; Displacement = 8;
//              IndexReg = X86::RAX; break;
//     case  6: NumBytes -=  6; Opc = X86::NOOPW; Displacement = 8;
//              IndexReg = X86::RAX; break;
//     case  7: NumBytes -=  7; Opc = X86::NOOPL; Displacement = 512; break;
//     case  8: NumBytes -=  8; Opc = X86::NOOPL; Displacement = 512;
//              IndexReg = X86::RAX; break;
//     case  9: NumBytes -=  9; Opc = X86::NOOPW; Displacement = 512;
//              IndexReg = X86::RAX; break;
//     default: NumBytes -= 10; Opc = X86::NOOPW; Displacement = 512;
//              IndexReg = X86::RAX; SegmentReg = X86::CS; break;

fn get_padding_for_length(length: u32) -> &'static [u8] {
    // nop
    // 90
    match length {
        1 =>
        // nop
        {
            &[0x90]
        }
        2 =>
        // xchg %ax,%ax
        {
            &[0x66, 0x90]
        }
        3 =>
        // nopl (%[re]ax)
        {
            &[0x0f, 0x1f, 0x00]
        }
        4 =>
        // nopl 0(%[re]ax)
        {
            &[0x0f, 0x1f, 0x40, 0x00]
        }
        5 =>
        // nopl 0(%[re]ax,%[re]ax,1)
        {
            &[0x0f, 0x1f, 0x44, 0x00, 0x00]
        }
        6 =>
        // nopw 0(%[re]ax,%[re]ax,1)
        {
            &[0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]
        }
        7 =>
        // nopl 0L(%[re]ax)
        {
            &[0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]
        }
        8 =>
        // nopl 0L(%[re]ax,%[re]ax,1)
        {
            &[0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
        }
        9 =>
        // nopw 0L(%[re]ax,%[re]ax,1)
        {
            &[0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
        }
        10 =>
        // nopw %cs:0L(%[re]ax,%[re]ax,1)
        {
            &[0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
        }
        11 =>
        // nopw %cs:0L(%[re]ax,%[re]ax,1)
        {
            &[
                0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        }
        12 =>
        // nopw 0(%[re]ax,%[re]ax,1)
        // nopw 0(%[re]ax,%[re]ax,1)
        {
            &[
                0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
            ]
        }
        13 =>
        // nopw 0(%[re]ax,%[re]ax,1)
        // nopl 0L(%[re]ax)
        {
            &[
                0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
            ]
        }
        14 =>
        // nopl 0L(%[re]ax)
        // nopl 0L(%[re]ax)
        {
            &[
                0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00,
            ]
        }
        15 =>
        // nopl 0L(%[re]ax)
        // nopl 0L(%[re]ax,%[re]ax,1)
        {
            &[
                0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
                0x00,
            ]
        }
        v => panic!("Nop for length {} not supported", v),
    }
}

pub fn get_padding_bytes(padding: u32) -> Vec<u8> {
    let mut padding_bytes = Vec::new();
    let mut rem_padding = padding;
    while rem_padding > 0 {
        let curr_round_padding = std::cmp::min(15, rem_padding);
        let bytes = get_padding_for_length(curr_round_padding);
        padding_bytes.extend_from_slice(&bytes);
        rem_padding -= curr_round_padding;
    }
    return padding_bytes;
}
