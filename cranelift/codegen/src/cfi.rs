use crate::cursor::{Cursor, EncCursor, FuncCursor};
use crate::ir::function::Function;
use crate::ir::instructions::{BranchInfo, Opcode};
use crate::ir::{types, InstBuilder, Value};
use crate::isa::TargetIsa;
use alloc::vec::Vec;

pub fn do_condbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);
    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Brz | Opcode::Brnz => {
                    let block1_label = cur.ins().iconst(types::I64, 42); // 42 standing in for the real label
                    let block2_label = cur.ins().iconst(types::I64, 54); // 54 standing in for the real label
                    let new_label = cur
                        .ins()
                        .condbr_get_new_cfi_label(block1_label, block2_label);

                    let brinfo = cur.func.dfg.analyze_branch(inst);
                    let (dest, varargs) = match brinfo {
                        BranchInfo::SingleDest(dest, varargs) => (dest, varargs),
                        _ => panic!("Expected Brz / Brnz to be a SingleDest"),
                    };
                    let varargs: Vec<Value> = varargs.to_vec(); // end immutable borrow of cur
                    let condition = cur.func.dfg.inst_args(inst)[0];

                    // replace the branch instruction with the corresponding CFI branch instruction
                    match opcode {
                        Opcode::Brz => { cur.ins().brz_cfi(condition, new_label, dest, &varargs[..]); }
                        Opcode::Brnz => { cur.ins().brnz_cfi(condition, new_label, dest, &varargs[..]); }
                        _ => { panic!("Shouldn't ever get here"); },
                    }
                    cur.remove_inst();
                }
                // Opcode::BrIcmp | Opcode::Brif | Opcode::Brff => unimplemented!(),
                _ => {}
            }
        }
    }
}

pub fn do_br_cfi(func: &mut Function, isa: &dyn TargetIsa) {
     let mut cur: EncCursor = EncCursor::new(func, isa);
     while let Some(block) = cur.next_block() {
         cur.goto_last_inst(block);
         let term = cur.current_inst().unwrap();
         let opcode = cur.func.dfg[term].opcode();
         match opcode {
             Opcode::Jump | Opcode::Fallthrough => {
                 match get_previous_opcode(&mut cur) {
                     Some(Opcode::Brz)
                     | Some(Opcode::BrzCfi)
                     | Some(Opcode::Brnz)
                     | Some(Opcode::BrnzCfi)
                     | Some(Opcode::BrIcmp)
                     | Some(Opcode::Brif)
                     | Some(Opcode::Brff)
                     => {} // do nothing, as this previous condbr instruction will handle cfi labels
                     _ => {
                        // we need to handle cfi label ourselves
                        let new_label = cur.ins().iconst(types::I64, 42); // 42 standing in for the real label
                        cur.ins().conditionally_set_cfi_label(new_label);
                     }
                 }
             }
             _ => {}
         }
     }
}

fn get_previous_opcode(cur: &mut EncCursor) -> Option<Opcode> {
    let saved_position = cur.position();
    let opcode = cur.prev_inst().map(|inst| {
        cur.func.dfg[inst].opcode()
    });
    cur.set_position(saved_position);
    opcode
}

// Assign a unique Cfi number to each linear blocks
pub fn do_cfi_number_allocate(func: &mut Function, cfi_start_num: &mut u64) {
    let mut cur = FuncCursor::new(func);

    while let Some(block) = cur.next_block() {
        cur.func.cfi_block_nums[block] = Some(*cfi_start_num);
        *cfi_start_num += 1;

        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();

            if !opcode.is_terminator()
                && (opcode.is_call() || opcode.is_branch() || opcode.is_indirect_branch())
            {
                cur.func.cfi_inst_nums[inst] = Some(*cfi_start_num);
                *cfi_start_num += 1;
            }
        }
    }
}
