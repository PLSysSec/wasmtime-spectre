use crate::cursor::{Cursor, EncCursor};
use crate::ir::{Block, Inst, InstBuilder, InstructionData, Value, ValueDef, ValueLoc, types};
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

const DEBUG_PRINT_THIS_FUNCTION: &'static str = "guest_func_main";
const DEBUG_DONT_INSTRUMENT_THESE_FUNCTIONS: &'static [&'static str] = &[
    "dlmalloc",
];

/// Used for debugging: should we print the current function
fn should_print() -> bool {
    let cur_func = cranelift_spectre::inst::get_curr_func();
    cur_func.starts_with(DEBUG_PRINT_THIS_FUNCTION)
}

/// Used for debugging: should we instrument the current function
fn should_instrument() -> bool {
    let cur_func = cranelift_spectre::inst::get_curr_func();
    if DEBUG_DONT_INSTRUMENT_THESE_FUNCTIONS.iter().any(|&f| cur_func.starts_with(f)) {
        false
    } else {
        true
    }
}

pub fn do_condbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at top of do_condbr_cfi:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Brz | Opcode::Brnz | Opcode::Brif | Opcode::Brff => {
                    let saved_position = cur.position();
                    if opcode == Opcode::Brif || opcode == Opcode::Brff {
                        // we need to insert the rest of our CFI stuff before the cmp,
                        // not before the branch itself, in order to not disrupt the flags
                        set_prev_valid_insert_point(&mut cur);
                    }
                    let new_label = {
                        let block1_label = cur.ins().iconst(types::I64, REPLACE_LABEL_1 as i64);
                        let block2_label = cur.ins().iconst(types::I64, REPLACE_LABEL_2 as i64);
                        cur.ins().condbr_get_new_cfi_label(block1_label, block2_label)
                    };

                    let (dest, varargs): (Block, Vec<Value>) = {
                        let brinfo = cur.func.dfg.analyze_branch(inst);
                        match brinfo {
                            BranchInfo::SingleDest(dest, varargs) => {
                                (dest, varargs.to_vec()) // end immutable borrow of cur
                            }
                            _ => panic!("Expected conditional branch to be a SingleDest"),
                        }
                    };

                    // replace the branch instruction with the corresponding CFI branch instruction
                    cur.set_position(saved_position);
                    cur.remove_inst();
                    match opcode {
                        Opcode::Brz => {
                            let condition = cur.func.dfg.inst_args(inst)[0];
                            cur.ins().brz_cfi(condition, new_label, dest, &varargs[..]);
                        }
                        Opcode::Brnz => {
                            let condition = cur.func.dfg.inst_args(inst)[0];
                            cur.ins().brnz_cfi(condition, new_label, dest, &varargs[..]);
                        }
                        Opcode::Brif => {
                            let condition = match &cur.func.dfg[inst] {
                                InstructionData::BranchInt { cond, .. } => *cond,
                                idata => panic!("Expected BranchInt, got {:?}", idata),
                            };
                            let flags = cur.func.dfg.inst_args(inst)[0];
                            cur.ins().brif_cfi(condition, flags, new_label, dest, &varargs[..]);
                        }
                        Opcode::Brff => {
                            let condition = match &cur.func.dfg[inst] {
                                InstructionData::BranchFloat { cond, .. } => *cond,
                                idata => panic!("Expected BranchFloat, got {:?}", idata),
                            };
                            let flags = cur.func.dfg.inst_args(inst)[0];
                            cur.ins().brff_cfi(condition, flags, new_label, dest, &varargs[..]);
                        }
                        _ => { panic!("Shouldn't ever get here"); },
                    };
                }
                Opcode::BrIcmp => {
                    unimplemented!("BrIcmp in do_condbr_cfi pass")
                }
                _ => {}
            }
        }
    }

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at bottom of do_condbr_cfi:\n{}", cur.func.display(isa));
    }
}

pub fn do_br_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at top of do_br_cfi:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Jump | Opcode::Fallthrough | Opcode::Call | Opcode::CallIndirect => {
                    if get_prev_opcode(&mut cur).map(|o| o.is_branch()) == Some(true) {
                        // do nothing, as this previous condbr instruction will handle cfi labels
                        let _a = 1;
                    } else {
                        // we need to handle cfi label ourselves
                        let new_label = cur.ins().iconst(types::I64, REPLACE_LABEL_1 as i64);
                        cur.ins().conditionally_set_cfi_label(new_label);
                    }

                    // TODO: DISABLED FOR NOW
                    // // For calls, we also need to pass in the return label as the first parameter
                    // if opcode == Opcode::Call  { // || opcode == Opcode::CallIndirect
                    //     // normally first param to a function is the sbx heap
                    //     // but we always use pinned heap regs when using cfi
                    //     // so let's reuse the now unused first param of the function to pass the return label
                    //     let is_hostcall = is_hostcall(&cur, inst);
                    //     if is_hostcall {
                    //         let ret_label_inst = cur.ins().get_pinned_reg(isa.pointer_type());
                    //         let call_args = cur.func.dfg.inst_args_mut(inst);
                    //         std::mem::replace(&mut call_args[0], ret_label_inst);
                    //     } else {
                    //         let ret_label_inst = cur.ins().iconst(types::I64, REPLACE_LABEL_2 as i64);
                    //         let call_args = cur.func.dfg.inst_args_mut(inst);
                    //         std::mem::replace(&mut call_args[0], ret_label_inst);
                    //     }
                    // }
                },
                // TODO: DISABLED FOR NOW
                // Opcode::Load => {
                //     // since we are replacing the first param with the CFI return label
                //     // we need to replace all prior uses of the first param
                //     // in particular some loads use this instead of the pinned reg
                //     let load_args = cur.func.dfg.inst_args(inst);
                //     if load_args.len() != 1 {
                //         return;
                //     }
                //     let arg = load_args[0];
                //     // context arg
                //     let value_num = arg.as_u32();
                //     if value_num == 0
                //     {
                //         let _a = 1;
                //         let heap_base = cur.ins().get_pinned_reg(isa.pointer_type());
                //         let load_args_mut = cur.func.dfg.inst_args_mut(inst);
                //         std::mem::replace(&mut load_args_mut[0], heap_base);
                //     }
                //     let _a = 1;
                // }
                Opcode::Return => {
                    let new_label = cur.ins().iconst(types::I64, RETURN_LABEL as i64);
                    cur.ins().conditionally_set_cfi_label(new_label);
                }
                _ => {}
            }
        }
    }

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at bottom of do_br_cfi:\n {}", cur.func.display(isa));
    }
}

/// Sets the cursor to immediately before the most recent instruction that
/// writes the CPU flags.  (This gives an insertion point where we don't
/// have to worry about clobbering the flags.)
fn set_prev_valid_insert_point(cur: &mut EncCursor) {
    loop {
        match cur.current_inst() {
            None => {
                let block = cur.current_block().unwrap();
                cur.goto_first_insertion_point(block);
                return;
            }
            Some(inst) => {
                let opcode = cur.func.dfg[inst].opcode();
                if opcode.writes_cpu_flags() {
                    return;
                }
            }
        }
        cur.prev_inst();
    }
}

/// Assign a unique CFI number to each linear block
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

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at top of do_cfi_add_checks:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

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
                add_cfi_func_checks(&mut cur, can_be_indirectly_called);
            }
            if first_inst_in_block {
                add_cfi_block_checks(&mut cur, first_inst_in_func);
            }

            add_cfi_inst_checks(&mut cur, &inst);

            first_inst_in_block = false;
            first_inst_in_func = false;
        }
    }

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at bottom of do_cfi_add_checks:\n{}", cur.func.display(isa));
    }
}

/// Set the correct CFI labels for each branch, jump, call etc instruction
/// (see notes on `set_labels_for_condbranch()` and `set_labels_for_uncondbranch()`)
pub fn do_cfi_set_correct_labels(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur = EncCursor::new(func, isa);

    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            if opcode == Opcode::BrzCfi || opcode == Opcode::BrnzCfi || opcode == Opcode::BrifCfi || opcode == Opcode::BrffCfi {
                set_labels_for_condbranch(&mut cur, inst);
            } else if opcode == Opcode::Jump || opcode == Opcode::Fallthrough || opcode == Opcode::Call || opcode == Opcode::CallIndirect {
                set_labels_for_uncondbranch(isa, &mut cur, inst);
            } else if opcode.is_branch() {
                panic!("Shouldn't see any conditional branch opcode here, they should all have been either handled in one of the above ifs or not exist during this pass. Found a {}", opcode);
            }
        }
    }
}

fn add_cfi_func_checks(cur: &mut EncCursor, can_be_indirectly_called: bool) {
    if can_be_indirectly_called {
        let block = cur.current_block().unwrap();
        // we now always zero the stack and heap in event of misprediction, to simplify chaining / avoid the control flow laundering problem
        //let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        let label = cur.func.cfi_block_nums[block].unwrap();
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, true, true);
        cur.func.block_guards[block].append(&mut bytes);
    }
}

fn add_cfi_block_checks(cur: &mut EncCursor, is_first_block: bool) {
    let saved_cursor_position = cur.position();

    let block = cur.current_block().unwrap();
    // Add the cfi check for each block
    if cur.func.block_guards[block].len() == 0 {
        // we now always zero the stack and heap in event of misprediction, to simplify chaining / avoid the control flow laundering problem
        //let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        let label = if is_first_block { FIRST_BLOCK_LABEL } else { cur.func.cfi_block_nums[block].unwrap() };
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, true, true);
        cur.func.block_guards[block].append(&mut bytes);
    }

    cur.set_position(saved_cursor_position);
}

fn add_cfi_inst_checks(cur: &mut EncCursor, inst: &Inst) {
    let opcode = cur.func.dfg[*inst].opcode();
    let _format = opcode.format();

    // Here we add "top-of-block" CFI checks for "blocks" which are only parts of Cranelift blocks
    if !opcode.is_terminator()
        && (opcode.is_call() || is_condbr_followed_by_non_jump_or_fallthrough(cur, opcode))
    {
        // we now always zero the stack and heap in event of misprediction, to simplify chaining / avoid the control flow laundering problem
        /*
        cur.next_inst();
        let (zero_heap, zero_stack) = is_heap_or_stack_op_before_next_ctrl_flow(isa, cur, divert);
        cur.prev_inst();
        */
        let label = cur.func.cfi_inst_nums[*inst].unwrap();
        let mut bytes = cranelift_spectre::inst::get_cfi_check_bytes(label, true, true);
        cur.func.post_inst_guards[*inst].append(&mut bytes);
    }
}

/// Put in the correct real CFI numbers prior to conditional branch, replacing
/// the placeholder numbers added in a previous pass.
///
/// `inst` should be a conditional branch instruction.
///
/// This function preserves the cursor position.
fn set_labels_for_condbranch(cur: &mut EncCursor, inst: Inst) {
    let cfi_label_inst = get_previous_cfi_label_inst(cur).unwrap();
    let br_block = match cur.func.dfg.analyze_branch(inst) {
        BranchInfo::SingleDest(dest, _) => dest,
        _ => {
            panic!("set_labels_for_branch: expected inst to be a SingleDest branch but it wasn't: {:?}", cur.func.dfg[inst].opcode());
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
                cur.func.cfi_inst_nums[inst].unwrap()
            }
        }
    };

    let args = cur.func.dfg.inst_args(cfi_label_inst);
    assert!(args.len() == 2, "Expected two CFI labels");

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
}

/// Put in the correct real CFI numbers prior to unconditional branch, replacing
/// the placeholder numbers added in a previous pass.
///
/// `inst` should be an unconditional branch or call instruction.
///
/// This function preserves the cursor position.
fn set_labels_for_uncondbranch(_isa: &dyn TargetIsa, cur: &mut EncCursor, inst: Inst) {
    let cfi_label_inst = get_previous_conditional_cfi_label_inst(cur);
    if cfi_label_inst.is_none() { return; }
    let cfi_label_inst = cfi_label_inst.unwrap();

    let opcode = cur.func.dfg[inst].opcode();
    let br_block_label =  if opcode == Opcode::Call || opcode == Opcode::CallIndirect {
        FIRST_BLOCK_LABEL
    } else {
        let br_block = match cur.func.dfg.analyze_branch(inst) {
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

    // TODO: DISABLED FOR NOW
    // // For calls, we also need to pass in the return label as the first parameter
    // if opcode == Opcode::Call  { // || opcode == Opcode::CallIndirect
    //     let is_hostcall = is_hostcall(&cur, inst);

    //     if !is_hostcall {
    //         let post_call_label = cur.func.cfi_inst_nums[inst].unwrap();
    //         // normally first param to a function is the sbx heap
    //         // but we always use pinned heap regs when using cfi
    //         // so let's reuse the now unused first param of the function to pass the return label
    //         let call_args = cur.func.dfg.inst_args(inst);
    //         let call_label_source = cur.func.dfg.value_def(*call_args.first().unwrap());
    //         let call_label_inst = match call_label_source {
    //             ValueDef::Result(inst, _) => inst,
    //             _ => panic!("Unexpected label source for CFI"),
    //         };
    //         cur.func.dfg.replace(call_label_inst).iconst(types::I64, post_call_label as i64);
    //     }
    // }
}

/// Get the first previous inst with opcode == Opcode::CondbrGetNewCfiLabel
///
/// This function preserves the cursor position.
fn get_previous_cfi_label_inst(cur: &mut EncCursor) -> Option<Inst> {
    // this should be in the same block, so only iterate in this block
    let saved_cursor_position = cur.position();

    let found = loop {
        match cur.current_inst() {
            None => break None,
            Some(cur_inst) => {
                let opcode = cur.func.dfg[cur_inst].opcode();
                if opcode ==  Opcode::CondbrGetNewCfiLabel {
                    break Some(cur_inst);
                }
            }
        }
        cur.prev_inst();
    };

    cur.set_position(saved_cursor_position);
    return found;
}

/// Get previous inst with opcode == ConditionallySetCfiLabel
/// If the previous instruction is a conditional branch this won't exist
///
/// This function preserves the cursor position.
fn get_previous_conditional_cfi_label_inst(cur: &mut EncCursor) -> Option<Inst> {
    let saved_cursor_position = cur.position();

    let found = loop {
        cur.prev_inst();
        match cur.current_inst() {
            None => break None,
            Some(cur_inst) => {
                match cur.func.dfg[cur_inst].opcode() {
                    Opcode::ConditionallySetCfiLabel => {
                        break Some(cur_inst);
                    }
                    o if o.is_branch() => {
                        break get_previous_cfi_label_inst(cur);
                    }
                    _ => {}
                }
            }
        }
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

/// Finds the most recent compare instruction which returns flags.
///
/// This function preserves the cursor position.
fn get_prev_inst_which_returns_flags(cur: &mut EncCursor) -> Option<Inst> {
    let saved_cursor_position = cur.position();

    let found = loop {
        match cur.current_inst() {
            None => break None,
            Some(cur_inst) => {
                if is_a_cmp_instruction_returning_flags(cur.func.dfg[cur_inst].opcode()) {
                    break Some(cur_inst);
                }
            }
        }
        cur.prev_inst();
    };

    cur.set_position(saved_cursor_position);
    return found;
}

/// Is this a cmp instruction that returns the flags
fn is_a_cmp_instruction_returning_flags(opcode: Opcode) -> bool {
    match opcode {
        Opcode::IfcmpImm
        | Opcode::Ifcmp
        | Opcode::IfcmpSp => true,
        // note that Opcode::Icmp and Opcode::IcmpImm do not return flags - they return bool results
        _ => false,
    }
}

fn get_registers<'a>(func: &'a Function, divert: &'a RegDiversions, values: impl IntoIterator<Item = Value> + 'a) -> impl Iterator<Item = RegUnit> + 'a {
    values.into_iter().filter_map( move |v| {
        match divert.get(v, &func.locations) {
            ValueLoc::Reg(r) => Some(r),
            _ => None,
        }
    })
}

fn is_heap_op(isa: &dyn TargetIsa, opcode: Opcode, mut in_regs: impl Iterator<Item = RegUnit>) -> bool {
    let r15 = isa.register_info().parse_regunit("r15").unwrap();
    if opcode.can_load() || opcode.can_store() {
        in_regs.any(|r| r == r15)
    } else {
        false
    }
}

fn is_stack_op(isa: &dyn TargetIsa, opcode: Opcode, mut in_regs: impl Iterator<Item = RegUnit>) -> bool {
    let rsp = isa.register_info().parse_regunit("rsp").unwrap();
    if opcode.can_load() || opcode.can_store() {
        opcode == Opcode::X86Push
            || opcode == Opcode::X86Pop
            || opcode == Opcode::Spill
            || opcode == Opcode::Fill
            || opcode == Opcode::Regspill
            || opcode == Opcode::Regfill
            || in_regs.any(|r| r == rsp)
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
        let mut in_regs = get_registers(&cur.func, &divert, args.iter().copied());
        // let _rets = cur.func.dfg.inst_results(cur_inst);
        // let _out_regs = get_registers(&cur.func, &divert, _rets.iter().copied());

        found_heap_op |= is_heap_op(isa, opcode, in_regs.by_ref());
        found_stack_op |= is_stack_op(isa, opcode, in_regs);

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
