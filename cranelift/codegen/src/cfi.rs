use crate::cursor::{Cursor, EncCursor, FuncCursor};
use crate::ir;
use crate::ir::function::Function;
use crate::ir::instructions::Opcode;
use crate::ir::InstBuilder;
use crate::isa::TargetIsa;

pub fn do_condbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);
    while let Some(block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Brz | Opcode::Brnz => {
                    let block1_label = cur.ins().iconst(ir::types::I32, 42); // 42 standing in for the real label
                    let block2_label = cur.ins().iconst(ir::types::I32, 54); // 54 standing in for the real label
                    let new_label = cur
                        .ins()
                        .condbr_get_new_cfi_label(block1_label, block2_label);
                    let condition_var = cur.func.dfg.inst_args(inst)[0].clone();
                    let int_condition_var = if cur.func.dfg.value_type(condition_var).is_bool() {
                        cur.ins().bint(ir::types::I32, condition_var)
                    } else {
                        condition_var
                    };
                    let flags_val = cur.ins().ifcmp_imm(int_condition_var, 0);
                    let condcode = match opcode {
                        Opcode::Brz => ir::condcodes::IntCC::Equal,
                        Opcode::Brnz => ir::condcodes::IntCC::NotEqual,
                        _ => panic!("Shouldn't ever get here"),
                    };

                    // here we need an instruction to cmov new_label into r14 based on the current flags
                    // r14 = cur.ins().selectif(ir::types::I32, condcode, flags_val, new_label, r14)

                    // now the existing br instruction based on the same current flags and `condcode`
                    // which we never removed, so hopefully it's in the right place?
                }
                Opcode::BrIcmp | Opcode::Brif | Opcode::Brff => unimplemented!(),
                _ => {}
            }
        }
    }
}

// Assign a unique Cfi number to each linear blocks
pub fn do_cfi_number_allocate(func: &mut Function, cfi_start_num: &mut u64) {
    let mut cur = FuncCursor::new(func);

    while let Some(block) = cur.next_block() {
        cur.func.cfi_block_nums[block] = *cfi_start_num;
        *cfi_start_num += 1;

        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();

            if !opcode.is_terminator()
                && (opcode.is_call() || opcode.is_branch() || opcode.is_indirect_branch())
            {
                cur.func.cfi_inst_nums[inst] = *cfi_start_num;
                *cfi_start_num += 1;
            }
        }
    }
}
