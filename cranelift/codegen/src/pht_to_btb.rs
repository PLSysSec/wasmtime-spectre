use crate::cursor::{Cursor, FuncCursor};
use crate::flowgraph::ControlFlowGraph;
use crate::ir::instructions::BranchInfo;
use crate::ir::{self, Function, JumpTableData};

use crate::ir::InstBuilder;
use crate::isa::TargetIsa;

use alloc::string::String;
use alloc::vec::Vec;

pub fn do_pht_to_btb(func: &mut Function, cfg: &mut ControlFlowGraph, _isa: &dyn TargetIsa) {
    let mut repeat = true;

    'outer: while repeat {
        repeat = false;

        let mut cur = FuncCursor::new(func);

        while let Some(_) = cur.next_block() {
            while let Some(inst) = cur.next_inst() {
                let opcode = cur.func.dfg[inst].opcode();
                let _enc = cur.func.encodings[inst];

                if opcode == ir::Opcode::Select {
                    panic!("pht_to_btb does not support select instruction. Run replace_select pass first");
                }

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

// Replace select instructions which would otherwise get expanded to branches much later
pub fn do_replace_selects(func: &mut Function, cfg: &mut ControlFlowGraph, _isa: &dyn TargetIsa) {
    // let cur_func = cranelift_spectre::inst::get_curr_func();
    // if cur_func == "guest_func_spec_singleBranch" {
    //     println!("Function at top of do_pht_to_btb:\n{}", func.display(_isa));
    // }

    let mut cur = FuncCursor::new(func);
    while let Some(_) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            if opcode == ir::Opcode::Select {

                let (ctrl, tval, fval) = match cur.func.dfg[inst] {
                    ir::InstructionData::Ternary {
                        opcode: ir::Opcode::Select,
                        args,
                    } => (args[0], args[1], args[2]),
                    _ => panic!("Expected select: {}", cur.func.dfg.display_inst(inst, None)),
                };

                let ty = cur.func.dfg.value_type(tval);
                if ty.is_int() {
                    // Replace `result = select ctrl, tval, fval` with:
                    //
                    //   ifcmp_imm ctrl, 0
                    //   result = selectif flags, tval, fval
                    let ctrl_ty = cur.func.dfg.value_type(ctrl);
                    let ctrl_int = if ctrl_ty.is_int() {
                        ctrl
                    } else {
                        cur.ins().bint(ir::types::I32, ctrl)
                    };
                    let flags_val = cur.ins().ifcmp_imm(ctrl_int, 0);
                    cur.func.dfg.replace(inst).selectif(ty, ir::condcodes::IntCC::NotEqual, flags_val, tval, fval);

                    cfg.recompute_block(cur.func, cur.current_block().unwrap());
                    // let new_inst = pos.ins().selectif(ty, ir::condcodes::IntCC::NotEqual, flags_val, tval, fval);
                    // let old = pos.func.dfg.first_result(inst);
                    // pos.func.dfg.replace_result(new_inst, new_inst);
                    // pos.remove_inst();
                } else {
                    // Replace `result = select ctrl, tval, fval` with:
                    //
                    //   brnz ctrl, new_block(tval)
                    //   jump new_block(fval)
                    // new_block(result):
                    let old_block = cur.current_block().unwrap();
                    let result = cur.func.dfg.first_result(inst);
                    cur.func.dfg.clear_results(inst);
                    let new_block = cur.func.dfg.make_block();
                    cur.func.dfg.attach_block_param(new_block, result);

                    cur.func.dfg.replace(inst).brnz(ctrl, new_block, &[tval]);
                    cur.goto_inst(inst);
                    cur.next_inst();
                    cur.use_srcloc(inst);
                    cur.ins().jump(new_block, &[fval]);
                    cur.insert_block(new_block);

                    cfg.recompute_block(cur.func, new_block);
                    cfg.recompute_block(cur.func, old_block);
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
    if opcode == ir::Opcode::Brif || opcode == ir::Opcode::Brff || opcode == ir::Opcode::BrIcmp {
        let _a = 1;
    }
    if !(opcode == ir::Opcode::Brnz || opcode == ir::Opcode::Brz) {
        panic!("Unsupported opcode for btb to pht: {:?}", opcode);
    }

    let args: Vec<_> = cur.func.dfg.inst_args(inst).iter().cloned().collect();

    let vv = args[0].clone();
    let t = cur.func.dfg.value_type(vv);
    let _t_str = to_debug(&t);

    let (br_block, jump_args) = match cur.func.dfg.analyze_branch(inst) {
        BranchInfo::SingleDest(dest, jump_args) => (dest, jump_args),
        _ => {
            panic!("Unexpected branch info");
        }
    };

    let jump_args: Vec<ir::Value> = jump_args.iter().cloned().collect();

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
