use crate::cursor::{Cursor, FuncCursor};
use crate::flowgraph::ControlFlowGraph;
use crate::ir::{self, Function, JumpTableData};
use crate::ir::instructions::BranchInfo;

use crate::ir::InstBuilder;

use alloc::string::String;
use alloc::vec::Vec;

pub fn do_pht_to_btb(func: &mut Function, cfg: &mut ControlFlowGraph) {
    let mut repeat = true;

    'outer: while repeat {
        repeat = false;

        let mut cur = FuncCursor::new(func);

        while let Some(_) = cur.next_block() {
            while let Some(inst) = cur.next_inst() {
                let opcode = cur.func.dfg[inst].opcode();
                let _enc = cur.func.encodings[inst];

                if opcode.is_branch() && opcode != ir::Opcode::BrTable && opcode != ir::Opcode::Jump {
                    let ret = convert_branch_to_table(&mut cur, cfg);
                    if ret {
                        repeat = true;
                        continue 'outer;
                    }
                }
            }
        }
    }
}

fn to_debug(t: &ir::types::Type) -> String {
    use std::fmt::Write;
    let mut buf = String::new();
    buf.write_fmt(format_args!("{:?}", t))
       .expect("a Debug implementation returned an error unexpectedly");
    buf.shrink_to_fit();
    buf
}

fn convert_branch_to_table(cur: &mut FuncCursor, cfg: &mut ControlFlowGraph) -> bool {
    let inst = cur.current_inst().unwrap();
    let opcode = cur.func.dfg[inst].opcode();
    if opcode == ir::Opcode::Brif ||
        opcode == ir::Opcode::Brff ||
        opcode == ir::Opcode::BrIcmp {
        let _a = 1;
    }
    if !(opcode == ir::Opcode::Brnz || opcode == ir::Opcode::Brz) {
        panic!("Unsupported opcode for btb to pht: {:?}", opcode);
    }

    let args : Vec<_> = cur.func.dfg.inst_args(inst).iter().cloned().collect();

    let vv = args[0].clone();
    let t = cur.func.dfg.value_type(vv);
    let _t_str = to_debug(&t);

    let (br_block, jump_args) = match cur.func.dfg.analyze_branch(inst) {
        BranchInfo::SingleDest(dest, jump_args) => {
            (dest, jump_args)
        }
        _ => {
            panic!("Unexpected branch info");
        }
    };

    let jump_args : Vec<ir::Value> = jump_args.iter().cloned().collect();

    // Move remaining instructions to new block
    cur.next_inst().unwrap();

    let new_block = cur.func.dfg.make_block();
    cur.insert_block(new_block);

    let br_block = if jump_args.len() == 0 {
        br_block
    } else {
        // target block has a phi node
        // insert a dummy block that calls the target block with correct params
        let dummy_block = cur.func.dfg.make_block();
        cur.goto_bottom(new_block);
        cur.insert_block(dummy_block);
        cur.ins().jump(br_block, &jump_args);
        dummy_block
    };

    // Replace conditional with select_if & br_table
    cur.goto_after_inst(inst);


    let zero = cur.ins().iconst(ir::types::I32, 0);
    let one = cur.ins().iconst(ir::types::I32, 1);

    let flags_val =
        if opcode == ir::Opcode::Brnz || opcode == ir::Opcode::Brz {
            let variable = args[0].clone();
            let int_val = if t.is_bool() {
                cur.ins().bint(ir::types::I32, variable)
            } else {
                variable
            };
            cur.ins().ifcmp_imm(int_val, 0)
        } else {
            panic!("Unsupported");
        };

    let op = if opcode == ir::Opcode::Brnz {
        ir::condcodes::IntCC::NotEqual
    } else if opcode == ir::Opcode::Brz {
        ir::condcodes::IntCC::Equal
    } else {
        panic!("Unsupported");
    };

    // table index = 1 if arg op zero
    let table_index = cur.ins().selectif(ir::types::I32, op, flags_val, one, zero);
    let oob_block = new_block;

    let mut jt_data = JumpTableData::new();
    // table_index == 0 ==> fallthrough
    jt_data.push_entry(new_block);
    // table_index == 1 ==> branch
    jt_data.push_entry(br_block);

    let jt = cur.func.create_jump_table(jt_data);
    let brtable_inst = cur.ins().br_table(table_index, oob_block, jt);

    // We can elide bounds checks for this switch table since it always has 2 entries
    cur.func.brtable_no_bounds_check[brtable_inst] = true;
    cfg.compute(cur.func);

    cur.goto_inst(inst);
    cur.remove_inst();

    return true;
}
