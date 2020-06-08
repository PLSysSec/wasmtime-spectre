use crate::cursor::{Cursor, EncCursor};
use crate::ir::{self, Inst, InstBuilder, Value, ValueDef, ValueLoc, types};
use crate::ir::function::Function;
use crate::ir::instructions::{BranchInfo, Opcode};
use crate::isa::{registers::RegUnit, TargetIsa};
use alloc::vec::Vec;

use crate::regalloc::RegDiversions;

const REPLACE_LABEL_1: u64 = 5;
const REPLACE_LABEL_2: u64 = 6;
const FIRST_BLOCK_LABEL: u64 = 10;
const RETURN_LABEL: u64 = 10;
const FIXED_LABEL: u64 = 10;

pub fn do_condbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);
    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Brz | Opcode::Brnz | Opcode::Brif | Opcode::Brff => {
                    let saved_position = cur.position();
                    if opcode == Opcode::Brif || opcode == Opcode::Brff {
                        // if its a brif, prev inst is a cmp
                        // prev inst could be setting various flags
                        // we can't add new instructions between after flag set
                        set_prev_valid_insert_point(&mut cur);
                    }
                    let block1_label = cur.ins().iconst(types::I64, REPLACE_LABEL_1 as i64);
                    let block2_label = cur.ins().iconst(types::I64, REPLACE_LABEL_2 as i64);
                    let new_label = cur
                        .ins()
                        .condbr_get_new_cfi_label(block1_label, block2_label);

                    let brinfo = cur.func.dfg.analyze_branch(inst);
                    let (dest, varargs) = match brinfo {
                        BranchInfo::SingleDest(dest, varargs) => (dest, varargs),
                        _ => panic!("Expected conditional branch to be a SingleDest"),
                    };
                    let varargs: Vec<Value> = varargs.to_vec(); // end immutable borrow of cur
                    let condition = cur.func.dfg.inst_args(inst)[0];

                    // replace the branch instruction with the corresponding CFI branch instruction
                    match opcode {
                        Opcode::Brz => {
                            cur.ins().brz_cfi(condition, new_label, dest, &varargs[..]);
                            cur.set_position(saved_position);
                            cur.remove_inst();
                        }
                        Opcode::Brnz => {
                            cur.ins().brnz_cfi(condition, new_label, dest, &varargs[..]);
                            cur.set_position(saved_position);
                            cur.remove_inst();
                        }
                        Opcode::Brif | Opcode::Brff => {
                            // A later pass actually injects the cfi instruction
                            cur.set_position(saved_position);
                        }
                        _ => { panic!("Shouldn't ever get here"); },
                    }
                }
                Opcode::BrIcmp => {
                    let _a = 1;
                }
                _ => {}
            }
        }
    }
}

pub fn do_br_cfi(func: &mut Function, isa: &dyn TargetIsa) {
     let mut cur: EncCursor = EncCursor::new(func, isa);
     while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Jump | Opcode::Fallthrough | Opcode::Call | Opcode::CallIndirect => {
                    match get_prev_opcode(&mut cur) {
                        Some(Opcode::Brz)
                        | Some(Opcode::BrzCfi)
                        | Some(Opcode::Brnz)
                        | Some(Opcode::BrnzCfi)
                        | Some(Opcode::BrIcmp)
                        | Some(Opcode::Brif)
                        | Some(Opcode::Brff)
                        => {
                            // do nothing, as this previous condbr instruction will handle cfi labels
                            let _a = 1;
                        }
                        _ => {
                            // we need to handle cfi label ourselves
                            let new_label = cur.ins().iconst(types::I64, REPLACE_LABEL_1 as i64);
                            cur.ins().conditionally_set_cfi_label(new_label);
                        }
                    }
                },
                Opcode::Return => {
                    let new_label = cur.ins().iconst(types::I64, RETURN_LABEL as i64);
                    cur.ins().conditionally_set_cfi_label(new_label);
                }
                _ => {}
            }
        }
     }
}

fn set_prev_valid_insert_point(cur: &mut EncCursor) {
    let mut seen_write_flags = false;
    loop {
        match cur.current_inst() {
            None => {
                let block = cur.current_block().unwrap();
                cur.goto_first_insertion_point(block);
                return;
            }
            Some(inst) => {
                if seen_write_flags {
                    return;
                }
                let opcode = cur.func.dfg[inst].opcode();
                if opcode.writes_cpu_flags() {
                    seen_write_flags = true;
                }
                cur.prev_inst();
            }
        }
    }
}

// Assign a unique Cfi number to each linear blocks
pub fn do_cfi_number_allocate(func: &mut Function, isa: &dyn TargetIsa, cfi_start_num: &mut u64) {
    let mut cur = EncCursor::new(func, isa);

    while let Some(block) = cur.next_block() {
        cur.func.cfi_block_nums[block] =  Some(FIXED_LABEL);//Some(*cfi_start_num);
        *cfi_start_num += 1;

        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();

            if !opcode.is_terminator() {
                if opcode.is_branch() || opcode.is_indirect_branch() {
                    cur.func.cfi_inst_nums[inst] = Some(FIXED_LABEL);//Some(*cfi_start_num);
                    *cfi_start_num += 1;
                }
            }

            if opcode.is_call() {
                cur.func.cfi_inst_nums[inst] = Some(RETURN_LABEL);
            }
        }
    }
}


pub fn do_cfi_add_checks(func: &mut Function, isa: &dyn TargetIsa, can_be_indirectly_called: bool) {
    let mut cur = EncCursor::new(func, isa);
    let mut divert = RegDiversions::new();

    let mut first_inst_in_func = true;
    let mut first_inst_in_block;
    let encinfo = isa.encoding_info();

    while let Some(block) = cur.next_block() {
        divert.at_block(&cur.func.entry_diversions, block);

        first_inst_in_block = true;

        while let Some(inst) = cur.next_inst() {
            let _opcode = cur.func.dfg[inst].opcode();
            let _format = _opcode.format();
            let _enc =  encinfo.display(cur.func.encodings[inst]);
            if first_inst_in_func {
                cfi_func_checks(isa, &mut cur, &divert, can_be_indirectly_called);
            }
            if first_inst_in_block {
                cfi_block_checks(isa, &mut cur, &divert, first_inst_in_func);
            }

            cfi_inst_checks(isa, &mut cur, &divert, &inst);

            first_inst_in_block = false;
            first_inst_in_func = false;
        }
    }
}

fn cfi_func_checks(
    isa: &dyn TargetIsa,
    cur: &mut EncCursor,
    divert: &RegDiversions,
    can_be_indirectly_called: bool,
) {
    if can_be_indirectly_called {
        let block = cur.current_block().unwrap();
        let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        let label = cur.func.cfi_block_nums[block].unwrap();
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, zero_heap, zero_stack);
        cur.func.block_guards[block].append(&mut bytes);
    }
}

fn cfi_block_checks(isa: &dyn TargetIsa, cur: &mut EncCursor, divert: &RegDiversions, is_first_block: bool) {
    let saved_cursor_position = cur.position();

    let block = cur.current_block().unwrap();
    // Add the cfi check fpr each block
    if cur.func.block_guards[block].len() == 0 {
        let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        // if cur.func.cfi_block_nums[block].is_none() {
        //     let _a = 1;
        // }
        let label = if is_first_block { FIRST_BLOCK_LABEL } else { cur.func.cfi_block_nums[block].unwrap() };
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, zero_heap, zero_stack);
        cur.func.block_guards[block].append(&mut bytes);
    }

    cur.set_position(saved_cursor_position);
}

fn cfi_inst_checks(
    isa: &dyn TargetIsa,
    cur: &mut EncCursor,
    divert: &RegDiversions,
    inst: &Inst,
) {
    let opcode = cur.func.dfg[*inst].opcode();
    let _format = opcode.format();

    if !opcode.is_terminator()
        && (opcode.is_call() || is_condbr_followed_by_non_jump_or_fallthrough(cur, opcode))
    {
        cur.next_inst();
        let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        cur.prev_inst();
        let label = cur.func.cfi_inst_nums[*inst].unwrap();
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, zero_heap, zero_stack);
        cur.func.post_inst_guards[*inst].append(&mut bytes);
    }

    if opcode == Opcode::BrzCfi || opcode == Opcode::BrnzCfi || opcode == Opcode::Brif || opcode == Opcode::Brff {
        let cfi_label_inst = get_previous_cfi_label_inst(cur).unwrap();
        let br_block = match cur.func.dfg.analyze_branch(*inst) {
            BranchInfo::SingleDest(dest, _) => dest,
            _ => {
                panic!("Unexpected branch info");
            }
        };
        let br_block_label = cur.func.cfi_block_nums[br_block].unwrap();
        let fallthrough_block_label = {
            let next_inst = get_next_inst(cur);
            match next_inst.map(|next_inst| cur.func.dfg[next_inst].opcode()) {
                Some(Opcode::Jump) | Some(Opcode::Fallthrough) => {
                    // label of jump or fallthrough target
                    match cur.func.dfg.analyze_branch(next_inst.expect("Already checked that it's a Some here")) {
                        BranchInfo::SingleDest(dest, ..) => {
                            cur.func.cfi_block_nums[dest].unwrap()
                        }
                        _ => panic!("Expected Jump/Fallthrough to be SingleDest"),
                    }
                }
                _ => {
                    // actual label of the fallthrough block
                    cur.func.cfi_inst_nums[*inst].unwrap()
                }
            }
        };

        let args = cur.func.dfg.inst_args(cfi_label_inst);
        assert!(args.len() == 2, "Expected two CFI labels");
        let rets = cur.func.dfg.inst_results(cfi_label_inst);
        let out_regs = get_registers(&cur.func, divert, &rets);

        let original_label0_source = cur.func.dfg.value_def(args[0]);
        let original_label1_source = cur.func.dfg.value_def(args[1]);

        let original_label0_inst = match original_label0_source {
            ValueDef::Result(inst, _) => inst,
            _ => panic!("Unexpected label source for CFI"),
        };
        let original_label1_inst = match original_label1_source {
            ValueDef::Result(inst, _) => inst,
            _ => panic!("Unexpected label source for CFI"),
        };

        cur.func.dfg.replace(original_label0_inst).iconst(types::I64, br_block_label as i64);
        cur.func.dfg.replace(original_label1_inst).iconst(types::I64, fallthrough_block_label as i64);

        if opcode == Opcode::Brif {
            use ir::InstructionData::*;
            let cond_code: ir::condcodes::IntCC = match &cur.func.dfg[*inst] {
                BranchInt {
                    opcode: _,
                    args: _,
                    cond,
                    destination: _,
                } => {
                    cond.clone()
                },
                _ => panic!("unexpected instruction in cfi brif"),
            };

            use cranelift_spectre::inst::*;
            let label_reg = out_regs[0];
            let mut cmov_bytes =
                match cond_code.unsigned() {
                    ir::condcodes::IntCC::Equal => { get_cmove(R_R14, label_reg) },
                    ir::condcodes::IntCC::NotEqual => { get_cmovne(R_R14, label_reg) },
                    ir::condcodes::IntCC::UnsignedLessThan => { get_cmovb(R_R14, label_reg) },
                    ir::condcodes::IntCC::UnsignedGreaterThanOrEqual => { get_cmovae(R_R14, label_reg) },
                    ir::condcodes::IntCC::UnsignedGreaterThan => { get_cmova(R_R14, label_reg) },
                    ir::condcodes::IntCC::UnsignedLessThanOrEqual => { get_cmovbe(R_R14, label_reg) },
                    ir::condcodes::IntCC::Overflow => { get_cmovo(R_R14, label_reg) },
                    ir::condcodes::IntCC::NotOverflow => { get_cmovno(R_R14, label_reg) },
                    _ => {
                        panic!("Not impl")
                    }
                };
            cur.func.pre_inst_guards[*inst].append(&mut cmov_bytes);
        }
        else if opcode == Opcode::Brff {
            use ir::InstructionData::*;
            let cond_code: ir::condcodes::FloatCC = match &cur.func.dfg[*inst] {
                BranchFloat {
                    opcode: _,
                    args: _,
                    cond,
                    destination: _,
                } => {
                    cond.clone()
                },
                _ => panic!("unexpected instruction in cfi brif"),
            };

            let _prev = get_prev_inst(cur);
            let _prev_opcode =  cur.func.dfg[_prev.unwrap_or(*inst)].opcode();

            use cranelift_spectre::inst::*;
            let label_reg = out_regs[0];
            let mut cmov_bytes =
                match cond_code {
                    ir::condcodes::FloatCC::Ordered => { get_cmovnp(R_R14, label_reg) },
                    ir::condcodes::FloatCC::Unordered => { get_cmovp(R_R14, label_reg) },
                    ir::condcodes::FloatCC::Equal => { get_cmove(R_R14, label_reg) },
                    ir::condcodes::FloatCC::NotEqual => { get_cmovne(R_R14, label_reg) },
                    ir::condcodes::FloatCC::OrderedNotEqual => { get_cmovne(R_R14, label_reg) },
                    ir::condcodes::FloatCC::UnorderedOrEqual => { get_cmove(R_R14, label_reg) },
                    ir::condcodes::FloatCC::LessThan => { get_cmovb(R_R14, label_reg) },
                    ir::condcodes::FloatCC::LessThanOrEqual => { get_cmovbe(R_R14, label_reg) },
                    ir::condcodes::FloatCC::GreaterThan => { get_cmova(R_R14, label_reg) },
                    ir::condcodes::FloatCC::GreaterThanOrEqual => { get_cmovae(R_R14, label_reg) },
                    ir::condcodes::FloatCC::UnorderedOrLessThan => { get_cmovb(R_R14, label_reg) },
                    ir::condcodes::FloatCC::UnorderedOrLessThanOrEqual => { get_cmovbe(R_R14, label_reg) },
                    ir::condcodes::FloatCC::UnorderedOrGreaterThan => { get_cmova(R_R14, label_reg) },
                    ir::condcodes::FloatCC::UnorderedOrGreaterThanOrEqual => { get_cmovae(R_R14, label_reg) },
                };
            cur.func.pre_inst_guards[*inst].append(&mut cmov_bytes);
        }
    } else if opcode == Opcode::Jump || opcode == Opcode::Fallthrough || opcode == Opcode::Call || opcode == Opcode::CallIndirect {
        let _a = 1;
        let cfi_label_inst = get_previous_conditional_cfi_label_inst(cur);
        if cfi_label_inst.is_none() { return; }
        let cfi_label_inst = cfi_label_inst.unwrap();

        let br_block_label =  if opcode == Opcode::Call || opcode == Opcode::CallIndirect {
            FIRST_BLOCK_LABEL
        } else {
            let br_block = match cur.func.dfg.analyze_branch(*inst) {
                BranchInfo::SingleDest(dest, _) => dest,
                _ => {
                    panic!("Unexpected branch info");
                }
            };

            cur.func.cfi_block_nums[br_block].unwrap()
        };
        let args = cur.func.dfg.inst_args(cfi_label_inst);

        // cfi_label_inst may be CondbrGetNewCfiLabel or ConditionallySetCfiLabel
        // either way the last arg is the fallthrough destination
        let original_label0_source = cur.func.dfg.value_def(*args.last().unwrap());
        let original_label0_inst = match original_label0_source {
            ValueDef::Result(inst, _) => inst,
            _ => panic!("Unexpected label source for CFI"),
        };

        cur.func.dfg.replace(original_label0_inst).iconst(types::I64, br_block_label as i64);
    } else if opcode.is_branch() {
        panic!("Shouldn't see any conditonal branch opcode here, they should all have been either handled in one of the above ifs or not exist during this pass. Found a {}", opcode);
    }
}


fn get_previous_cfi_label_inst(cur: &mut EncCursor) -> Option<Inst> {
    // get prev inst which is opcode == Opcode::CondbrGetNewCfiLabel
    // this should be in the same block, so only iterate in this block
    let saved_cursor_position = cur.position();

    let found = loop {
        let cur_inst = cur.current_inst();
        if cur_inst.is_none() {
            break None;
        }

        let cur_inst = cur_inst.unwrap();
        let opcode = cur.func.dfg[cur_inst].opcode();
        if opcode ==  Opcode::CondbrGetNewCfiLabel {
            break Some(cur_inst);
        }
        cur.prev_inst();
    };

    cur.set_position(saved_cursor_position);
    return found;
}

// Get previous conditionally_set_cfi_label for a jump if it exists
// If the previous instruction is a conditional branch this won't exist
fn get_previous_conditional_cfi_label_inst(cur: &mut EncCursor) -> Option<Inst> {
    let saved_cursor_position = cur.position();

    let found = loop {
        let cur_inst = cur.current_inst();
        if cur_inst.is_none() {
            break None;
        }

        let cur_inst = cur_inst.unwrap();
        let opcode = cur.func.dfg[cur_inst].opcode();

        match opcode {
            Opcode::ConditionallySetCfiLabel => {
                break Some(cur_inst);
            }
            Opcode::Brz | Opcode::BrzCfi |
            Opcode::Brnz | Opcode::BrnzCfi |
            Opcode::BrIcmp | Opcode::Brif | Opcode::Brff => {
                break get_previous_cfi_label_inst(cur);
            }
            _ => {}
        }

        cur.prev_inst();
    };

    cur.set_position(saved_cursor_position);
    return found;
}

/// "Peeks" the next instruction without actually moving the cursor
fn get_next_inst(cur: &mut impl Cursor) -> Option<Inst> {
    let saved_position = cur.position();
    let inst = cur.next_inst();
    cur.set_position(saved_position);
    inst
}

/// "Peeks" the prev instruction without actually moving the cursor
fn get_prev_inst(cur: &mut impl Cursor) -> Option<Inst> {
    let saved_position = cur.position();
    let inst = cur.prev_inst();
    cur.set_position(saved_position);
    inst
}

fn get_next_opcode(cur: &mut EncCursor) -> Option<Opcode> {
    get_next_inst(cur).map(|inst| cur.func.dfg[inst].opcode())
}

fn get_prev_opcode(cur: &mut EncCursor) -> Option<Opcode> {
    get_prev_inst(cur).map(|inst| cur.func.dfg[inst].opcode())
}

fn get_registers(func: &Function, divert: &RegDiversions, values: &[Value]) -> Vec<RegUnit> {
    let mut regs = vec![];
    for value in values {
        let v = divert.get(*value, &func.locations);
        match v {
            ValueLoc::Reg(r) => regs.push(r),
            _ => (),
        };
    }
    regs
}

fn is_heap_op(isa: &dyn TargetIsa, opcode: Opcode, in_regs: &[RegUnit]) -> bool {
    let r15 = isa.register_info().parse_regunit("r15").unwrap();
    if opcode.can_load() || opcode.can_store() {
        in_regs.iter().any(|&r| r == r15)
    } else {
        false
    }
}

fn is_stack_op(isa: &dyn TargetIsa, opcode: Opcode, in_regs: &[RegUnit]) -> bool {
    let rsp = isa.register_info().parse_regunit("rsp").unwrap();
    if opcode.can_load() || opcode.can_store() {
        opcode == Opcode::X86Push
            || opcode == Opcode::X86Pop
            || opcode == Opcode::Spill
            || opcode == Opcode::Fill
            || opcode == Opcode::Regspill
            || opcode == Opcode::Regfill
            || in_regs.iter().any(|&r| r == rsp)
    } else {
        false
    }
}

/// Is there a heap operation or stack operation somewhere between where the
/// cursor is currently pointing (including the current instruction) and the next
/// control flow instruction (call, cond/uncond branch, etc)?
///
/// Returns a pair of `bool`s, where the first `bool` indicates whether there's a
/// heap op, and the second indicates whether there's a stack op
///
/// Preserves the cursor position.
fn is_heap_or_stack_op_before_next_ctrl_flow(
    isa: &dyn TargetIsa,
    cur: &mut EncCursor,
    divert: &RegDiversions,
) -> (bool, bool) {
    let saved_cursor_position = cur.position();
    let mut found_heap_op = false;
    let mut found_stack_op = false;
    loop {
        let cur_inst = cur.current_inst();
        if cur_inst.is_none() {
            break;
        }
        let cur_inst = cur_inst.unwrap();
        let opcode = cur.func.dfg[cur_inst].opcode();
        let args = cur.func.dfg.inst_args(cur_inst);
        let in_regs = get_registers(&cur.func, &divert, args);
        let _rets = cur.func.dfg.inst_results(cur_inst);
        let _out_regs = get_registers(&cur.func, &divert, _rets);

        found_heap_op |= is_heap_op(isa, opcode, &in_regs);
        found_stack_op |= is_stack_op(isa, opcode, &in_regs);

        if found_heap_op {
            let _a = 1;
        }
        if found_stack_op {
            let _a = 1;
        }
        if opcode.is_terminator()
            || opcode.is_branch()
            || opcode.is_indirect_branch()
            || opcode.is_call()
        {
            // reached next control flow operation
            break;
        }
        cur.next_inst();
    }
    // Restore the cursor position and return
    cur.set_position(saved_cursor_position);
    return (found_heap_op, found_stack_op);
}

fn is_condbr_followed_by_non_jump_or_fallthrough(cur: &mut EncCursor, opcode: Opcode) -> bool {
    if opcode.is_branch() || opcode.is_indirect_branch() {
        match get_next_opcode(cur) {
            Some(Opcode::Jump) | Some(Opcode::Fallthrough) => false,
            None => panic!("Condbr is last instruction in block, which shouldn't happen"),
            _ => true,
        }
    } else {
        false
    }
}
