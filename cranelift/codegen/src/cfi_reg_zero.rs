use crate::cursor::{Cursor, FuncCursor};
use crate::flowgraph::ControlFlowGraph;
use crate::ir::instructions::BranchInfo;
use crate::ir::{self, Block, Function, JumpTableData, Value};

use crate::ir::InstBuilder;
use crate::isa::TargetIsa;

use alloc::string::String;
use alloc::vec::Vec;

use crate::entity::SecondaryMap;

pub fn do_cfi_reg_zero(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur = FuncCursor::new(func);
    let mut add_heap_clear : SecondaryMap<Block, bool> = SecondaryMap::new();

    while let Some(block) = cur.next_block() {
        add_heap_clear[block] = false;
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            if opcode.can_load() || opcode.can_store() {
                add_heap_clear[block] = true;
                break;
            }
        }
    }

    let mut cur = FuncCursor::new(func);

    while let Some(block) = cur.next_block() {

        cur.goto_first_insertion_point(block);
        let cfi_val = cur.ins().iconst(ir::types::I64, 42);
        let inst = cur.prev_inst().unwrap();
        cur.next_inst();
        cur.func.marked[inst] = true;
        // let zero = cur.ins().allocate_reg(cfi_val);
        // set_encoding(&mut cur, isa);
        // let val2 = cur.ins().sextend(ir::types::I64, zero);
        // let cfi_val = cur.ins().iconst(ir::types::I64, 42);
        // let reg = cur.ins().cfi_zero_stack_reg(cfi_val, zero);
        // set_encoding(&mut cur, isa);

        // let reg = get_pinned_cf_reg_val(&mut cur, isa);
        // let stack = get_pinned_stack_reg_val(&mut cur, isa);

        // let cmp = cur.ins().ifcmp_imm(reg, 42);
        // let new_stack = cur.ins().selectif(ir::types::I64, ir::condcodes::IntCC::NotEqual, cmp, zero, stack);
        // set_pinned_stack_reg_val(&mut cur, isa, new_stack);

        // if add_heap_clear[block] {
        //     let heap = cur.ins().get_pinned_reg(ir::types::I64);
        //     let new_heap = cur.ins().selectif(ir::types::I64, ir::condcodes::IntCC::NotEqual, cmp, zero, heap);
        //     cur.ins().set_pinned_reg(new_heap);
        // }

        // while let Some(inst) = cur.next_inst() {

        // }

    }
}

fn set_encoding(cur: &mut FuncCursor, isa: &dyn TargetIsa) {
    let inst = cur.prev_inst().unwrap();
    let dfg = &cur.func.dfg;
    let ctrl_type = dfg.ctrl_typevar(inst);
    let enc = isa.legal_encodings(cur.func, &dfg[inst], ctrl_type).next().unwrap();
    cur.func.encodings[inst] = enc;
    cur.next_inst();
}
