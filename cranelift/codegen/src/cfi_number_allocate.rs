use crate::cursor::{Cursor, FuncCursor};
use crate::ir::Function;

// Assign a unique Cfi number to each linear blocks
pub fn do_cfi_number_allocate(func: &mut Function, cfi_start_num: &mut u64) {
    let mut cur = FuncCursor::new(func);

    while let Some(block) = cur.next_block() {
        cur.func.cfi_block_nums[block] = *cfi_start_num;
        *cfi_start_num += 1;

        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();

            if !opcode.is_terminator() &&
                (opcode.is_call() || opcode.is_branch() || opcode.is_indirect_branch())
            {
                cur.func.cfi_inst_nums[inst] = *cfi_start_num;
                *cfi_start_num += 1;
            }
        }
    }
}
