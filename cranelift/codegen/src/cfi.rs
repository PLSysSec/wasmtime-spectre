use crate::cursor::{Cursor, EncCursor};
use crate::dominator_tree::DominatorTree;
use crate::flowgraph::ControlFlowGraph;
use crate::loop_analysis::{Loop, LoopAnalysis};
use crate::ir::{Block, Inst, InstBuilder, InstructionData, Value, ValueLoc, types};
use crate::ir::function::Function;
use crate::ir::instructions::{BranchInfo, Opcode};
use crate::isa::{registers::RegUnit, TargetIsa};
use alloc::vec::Vec;

use crate::regalloc::RegDiversions;

const FIXED_LABEL: u64 = 10;
const REPLACE_LABEL_1: u64 = FIXED_LABEL; //5;
const REPLACE_LABEL_2: u64 = FIXED_LABEL; //6;
const FIRST_BLOCK_LABEL: u64 = 10;
const RETURN_LABEL: u64 = 10;
pub const PROBE_STACK_LABEL: u64 = 10;

// DEBUGMODE DISABLED BY DEFAULT. ONLY ENABLE FOR DEBUGGING
const DEBUG_PRINT_THIS_FUNCTION: &'static str = "____";
// DEBUGMODE DISABLED BY DEFAULT. ONLY ENABLE FOR DEBUGGING
const DEBUG_DONT_INSTRUMENT_THESE_FUNCTIONS: &'static [&'static str] = &[
    //"dlmalloc",
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

/// Insert the appropriate CFI boilerplate before each conditional branch
pub fn do_condbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur: EncCursor = EncCursor::new(func, isa);

    if should_print() {
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

                    cur.ins().set_cfi_label(REPLACE_LABEL_1 as i64);
                    let new_label = cur.ins().iconst(types::I64, REPLACE_LABEL_2 as i64);

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

    if should_print() {
        println!("Function at bottom of do_condbr_cfi:\n{}", cur.func.display(isa));
    }
}

/// Insert the appropriate CFI boilerplate before each unconditional jump
pub fn do_br_cfi(func: &mut Function, isa: &dyn TargetIsa, cfg: &ControlFlowGraph, domtree: &DominatorTree) {
    let mut cur: EncCursor = EncCursor::new(func, isa);

    if should_print() {
        println!("Function at top of do_br_cfi:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    let mut divert = RegDiversions::new();

    while let Some(block) = cur.next_block() {
        divert.at_block(&cur.func.entry_diversions, block);

        match cfi_can_skip_block(block, &mut cur, cfg, domtree, isa, &divert) {
            SkipResult::CanSkip { succ_block: _ } => {

                // println!("Block_num:{:?}\n", block);
                continue;
            }
            SkipResult::CantSkip => {}
        }

        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::Jump | Opcode::Fallthrough | Opcode::Call | Opcode::CallIndirect => {
                    if get_prev_opcode(&mut cur).map(|o| o.is_branch()) == Some(true) {
                        // do nothing, as this previous condbr instruction will handle cfi labels
                        let _a = 1;
                    } else {
                        // we need to handle cfi label ourselves
                        cur.ins().set_cfi_label(REPLACE_LABEL_1 as i64);
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
                    cur.ins().set_cfi_label(RETURN_LABEL as i64);
                }
                _ => {}
            }
        }
    }

    if should_print() {
        println!("Function at bottom of do_br_cfi:\n {}", cur.func.display(isa));
    }
}

/// Insert the appropriate CFI boilerplate surrounding indirect jumps (jump tables)
pub fn do_indirectbr_cfi(func: &mut Function, isa: &dyn TargetIsa) {
    let mut cur = EncCursor::new(func, isa);

    if should_print() {
        println!("Function at top of do_indirectbr_cfi:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            match opcode {
                Opcode::BrTable => {
                    panic!("This pass needs to run after BrTable has been legalized into smaller instructions");
                }
                Opcode::JumpTableEntry => {
                    // replace with JumpTableEntryCFI
                    let (args, imm, table) = match &cur.func.dfg[inst] {
                        InstructionData::BranchTableEntry { args, imm, table, .. } => (args.to_vec(), *imm, *table),
                        instdata => panic!("Expected a BranchTableEntry, got {:?}", instdata),
                    };
                    let result = cur.func.dfg.first_result(inst);
                    cur.func.dfg.detach_results(inst);
                    cur.remove_inst();
                    let _ = cur.ins().jump_table_entry_cfi(args[0], args[1], imm, table);
                    let new_inst = cur.built_inst();
                    cur.func.dfg.clear_results(new_inst);
                    cur.func.dfg.attach_result(new_inst, result);
                }
                Opcode::IndirectJumpTableBr => {
                    // We don't actually need to do anything for this -- everything
                    // was done in JumpTableEntryCFI
                }
                _ => {}
            }
        }
    }

    if cranelift_spectre::inst::DEBUG_MODE && should_print() {
        println!("Function at bottom of do_indirectbr_cfi:\n {}", cur.func.display(isa));
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
        cur.func.cfi_block_nums[block] = Some(FIXED_LABEL);//Some(*cfi_start_num);
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

pub fn do_cfi_add_checks(
    func: &mut Function,
    isa: &dyn TargetIsa,
    cfg: &ControlFlowGraph,
    domtree: &DominatorTree,
) {
    let mut cur = EncCursor::new(func, isa);

    if should_print() {
        println!("Function at top of do_cfi_add_checks:\n{}", cur.func.display(isa));
    }
    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    let mut divert = RegDiversions::new();

    let mut first_block_in_func = true;
    let mut first_inst_in_block;

    while let Some(block) = cur.next_block() {
        divert.at_block(&cur.func.entry_diversions, block);

        match cfi_can_skip_block(block, &mut cur, cfg, domtree, isa, &divert) {
            SkipResult::CanSkip { succ_block } => {
                cur.func.cfi_block_nums[block] = cur.func.cfi_block_nums[succ_block];
                continue;
            }
            SkipResult::CantSkip => {}
        }

        first_inst_in_block = true;

        while let Some(inst) = cur.next_inst() {
            if first_inst_in_block {
                add_cfi_block_check(&mut cur, first_block_in_func);
            }

            if needs_cfi_inst_check(&mut cur, inst) {
                add_cfi_inst_check(&mut cur, inst);
            }

            first_inst_in_block = false;
        }

        first_block_in_func = false;
    }

    if should_print() {
        println!("Function at bottom of do_cfi_add_checks:\n{}", cur.func.display(isa));
    }
}

enum SkipResult {
    CanSkip {
        succ_block: Block, // the successor block
    },
    CantSkip,
}

/// Can CFI skip the given `block`?
///
/// This function preserves the cursor position.
fn cfi_can_skip_block(
    block: Block,
    cur: &mut EncCursor,
    cfg: &ControlFlowGraph,
    domtree: &DominatorTree,
    isa: &dyn TargetIsa,
    divert: &RegDiversions,
) -> SkipResult {
    // CFI can skip the block if all of the following are true:
    //   - Block has exactly one predecessor
    //   - Block is dominated by its predecessor
    //   - Block has exactly one successor
    //   - Successor post-dominates Block - but this is implied by the bullet above
    //   - Block contains no heap operations
    // Making things more complicated, all of these things need to be computed
    // based on linear blocks, not Cranelift EBBs.
    // For now, we apply this optimization only to blocks which are both a
    // linear block and a Cranelift EBB - i.e., contain no call or
    // non-terminator branch instructions.
    let pred = {
        let mut preds = cfg.pred_iter(block);
        match preds.next() {
            None => return SkipResult::CantSkip, // Block has no predecessors
            Some(pred) => match preds.next() {
                None => pred, // Block has exactly one predecessor, this `pred`
                Some(_) => return SkipResult::CantSkip, // Block has >= 2 predecessors
            }
        }
    };
    let succ = {
        let mut succs = cfg.succ_iter(block);
        match succs.next() {
            None => return SkipResult::CantSkip, // Block has no successors
            Some(succ) => match succs.next() {
                None => succ, // Block has exactly one successor, this `succ`
                Some(_) => return SkipResult::CantSkip, // Block has >= 2 successors
            }
        }
    };
    if !domtree.dominates(pred.inst, block, &cur.func.layout) {
        // Pred does not dominate block
        return SkipResult::CantSkip;
    }
    if is_heap_op_in_block(cur, block, isa, divert) {
        // Block contains a heap operation
        return SkipResult::CantSkip;
    }
    if is_call_or_non_term_branch_in_block(cur, block) {
        // Block is not a Cranelift EBB - see notes above
        return SkipResult::CantSkip;
    }
    return SkipResult::CanSkip { succ_block: succ };
}

/// Set the correct CFI labels for each branch, jump, call etc instruction
/// (see notes on `set_labels_for_condbranch()` and `set_labels_for_uncondbranch()`)
pub fn do_cfi_set_correct_labels(_func: &mut Function, _isa: &dyn TargetIsa) {
    // TODO: DISABLED FOR NOW
    /*
    let mut cur = EncCursor::new(func, isa);

    if cranelift_spectre::inst::DEBUG_MODE && !should_instrument() {
        return
    }

    while let Some(_block) = cur.next_block() {
        while let Some(inst) = cur.next_inst() {
            let opcode = cur.func.dfg[inst].opcode();
            if opcode == Opcode::BrzCfi || opcode == Opcode::BrnzCfi || opcode == Opcode::BrifCfi || opcode == Opcode::BrffCfi {
                set_labels_for_condbranch(&mut cur, inst);
            } else if opcode == Opcode::BrzCfiLoopend || opcode == Opcode::BrnzCfiLoopend || opcode == Opcode::BrifCfiLoopend || opcode == Opcode::BrffCfiLoopend {
                TODO
            } else if opcode == Opcode::Jump || opcode == Opcode::Fallthrough || opcode == Opcode::Call || opcode == Opcode::CallIndirect {
                set_labels_for_uncondbranch(isa, &mut cur, inst);
            } else if opcode == Opcode::IndirectJumpTableBr {
                // these are handled all at once, below
            } else if opcode.is_branch() {
                panic!("Shouldn't see any branch opcode here, they should all have been either handled in one of the above ifs or not exist during this pass. Found a {}", opcode);
            }
        }
    }

    set_labels_for_jumptablebr(&mut cur.func);
    */
}

/// Optimize CFI checks in loops to prevent loop iteration serialization
pub fn do_cfi_loop_optimize(func: &mut Function, isa: &dyn TargetIsa, _cfg: &ControlFlowGraph, loop_analysis: &LoopAnalysis) {
    let mut cur = EncCursor::new(func, isa);

    // let cur_func = cranelift_spectre::inst::get_curr_func();
    // if cur_func.starts_with("guest_func_strlen") || cur_func.starts_with("guest_func_spec_printBranch2") {
    if should_print() {
        println!("Function at top of do_cfi_add_checks:\n{}", cur.func.display(isa));
    }

    for lp in loop_analysis.loops() {
        let loop_details = get_loop_details(&mut cur, isa, loop_analysis, lp);

        let opcode = cur.func.dfg[loop_details.branch_body].opcode();
        match opcode {
            Opcode::BrzCfi | Opcode::BrnzCfi | Opcode::BrifCfi | Opcode::BrffCfi => {
                apply_loopend_opt(&mut cur, loop_details);
            }
            Opcode::Jump => {
                // backwards edge is unconditional
                // remove_cfi_branch(&mut cur, loop_jump);
            }
            _ => {
            }
        }
    }
}

struct LoopDetails {
    header_block: Block,
    body_block: Block,
    exit_block: Block,
    branch_body: Inst,
    branch_exit: Inst,
    header_before_body: bool,
}
fn get_loop_details(cur: &mut EncCursor, isa: &dyn TargetIsa, loop_analysis: &LoopAnalysis, lp: Loop) -> LoopDetails {
    let header_block = loop_analysis.loop_header(lp);

    cur.goto_last_inst(header_block);
    let last_inst = cur.current_inst().unwrap();
    cur.prev_inst();
    let second_to_last_inst = cur.current_inst().unwrap();

    let (branch_body, branch_exit) =
        if branch_points_to_loop(cur, loop_analysis, lp, last_inst) {
            assert!(!branch_points_to_loop(cur, loop_analysis, lp, second_to_last_inst));
            (last_inst, second_to_last_inst)
        } else {
            assert!(branch_points_to_loop(cur, loop_analysis, lp, second_to_last_inst));
            (second_to_last_inst, last_inst)
        };

    let body_block = match cur.func.dfg.analyze_branch(branch_body) {
        BranchInfo::SingleDest(dest, _) => {
            dest
        }
        _ => { panic!("Expected branch") }
    };

    let exit_block = match cur.func.dfg.analyze_branch(branch_exit) {
        BranchInfo::SingleDest(dest, _) => {
            dest
        }
        _ => { panic!("Expected branch") }
    };

    let header_before_body = block_before(cur, isa, header_block, body_block);
    cur.goto_inst(branch_body);
    let ret = LoopDetails {
        header_block,
        body_block,
        exit_block,
        branch_body,
        branch_exit,
        header_before_body,
    };
    return ret;
}

fn branch_points_to_loop(cur: &mut EncCursor, loop_analysis: &LoopAnalysis, lp: Loop, inst: Inst) -> bool {
    let ret = match cur.func.dfg.analyze_branch(inst) {
        BranchInfo::SingleDest(dest, _) => {
            loop_analysis.is_in_loop(dest, lp)
        }
        _ => { panic!("Expected branch") }
    };
    return ret;
}

fn block_before(cur: &mut EncCursor, isa: &dyn TargetIsa, block_a: Block, block_b: Block) -> bool {
    let saved_position = cur.position();

    // go to the beginning
    while cur.prev_block().is_some() {}

    // Check if we see the block_a or block_b first
    let mut ret = None;
    while let Some(block) = cur.next_block() {
        if block == block_a {
            ret = Some(true);
            break;
        } else if block == block_b {
            ret = Some(false);
        }
    }

    cur.set_position(saved_position);
    return ret.unwrap();
}

/// Change loop CFI to prevent loop iteration serialization.
///
/// This amounts solely to changing brx_cfi to brx_cfi_loopend, and switching the
/// label that was set beforehand (from the fallthrough label, to the branch
/// label).
///
/// Callers should assume that this function _clobbers_ the cursor position.
fn apply_loopend_opt(cur: &mut EncCursor, loop_details: LoopDetails) {
    let branch_body = loop_details.branch_body;
    cur.goto_inst(branch_body);

    let (dest, varargs): (Block, Vec<Value>) = {
        let brinfo = cur.func.dfg.analyze_branch(branch_body);
        match brinfo {
            BranchInfo::SingleDest(dest, varargs) => {
                (dest, varargs.to_vec()) // end immutable borrow of cur
            }
            _ => panic!("Expected conditional branch to be a SingleDest"),
        }
    };

    // replace the CFI branch instruction with the corresponding CFI Loopend branch instruction
    let opcode = cur.func.dfg[branch_body].opcode();
    cur.remove_inst();
    match opcode {
        Opcode::BrzCfi => {
            let condition = cur.func.dfg.inst_args(branch_body)[0];
            let new_label = cur.func.dfg.inst_args(branch_body)[1];
            cur.ins().brz_cfi_loopend(condition, new_label, dest, &varargs[..]);
        }
        Opcode::BrnzCfi => {
            let condition = cur.func.dfg.inst_args(branch_body)[0];
            let new_label = cur.func.dfg.inst_args(branch_body)[1];
            cur.ins().brnz_cfi_loopend(condition, new_label, dest, &varargs[..]);
        }
        Opcode::BrifCfi => {
            let condition = match &cur.func.dfg[branch_body] {
                InstructionData::BranchIcmp /* BranchIntCFI */ { cond, .. } => *cond,
                idata => panic!("Expected BranchIntCFI, got {:?}", idata),
            };
            let flags = cur.func.dfg.inst_args(branch_body)[0];
            let new_label = cur.func.dfg.inst_args(branch_body)[1];
            cur.ins().brif_cfi_loopend(condition, flags, new_label, dest, &varargs[..]);
        }
        Opcode::BrffCfi => {
            let condition = match &cur.func.dfg[branch_body] {
                InstructionData::BranchFloatCFI { cond, .. } => *cond,
                idata => panic!("Expected BranchFloatCFI, got {:?}", idata),
            };
            let flags = cur.func.dfg.inst_args(branch_body)[0];
            let new_label = cur.func.dfg.inst_args(branch_body)[1];
            cur.ins().brff_cfi_loopend(condition, flags, new_label, dest, &varargs[..]);
        }
        _ => {
            panic!("Expected to find a CFI cond branch opcode, got {:?}", opcode);
        }
    }

    // TODO: need to change the label that was set
}

/// Convert loops with an unconditional forward edge (preceeded by a
/// conditional forward edge) to prevent loop iteration serialization.
///
/// This amounts solely to changing brx_cfi to brx and switching the
/// label check done on the exit to use the same label as the loop.
///
/// Callers should assume that this function _clobbers_ the cursor position.
fn remove_cfi_branch(cur: &mut EncCursor, forward_jump: Inst) {
    cur.goto_inst(forward_jump);
    let forward_exit = cur.prev_inst().unwrap();

    let (dest, varargs): (Block, Vec<Value>) = {
        let brinfo = cur.func.dfg.analyze_branch(forward_jump);
        match brinfo {
            BranchInfo::SingleDest(dest, varargs) => {
                (dest, varargs.to_vec()) // end immutable borrow of cur
            }
            _ => panic!("Expected conditional branch to be a SingleDest"),
        }
    };

    let opcode = cur.func.dfg[forward_exit].opcode();
    cur.remove_inst();
    match opcode {
        Opcode::BrzCfi => {
            let condition = cur.func.dfg.inst_args(forward_jump)[0];
            // let new_label = cur.func.dfg.inst_args(forward_jump)[1];
            cur.ins().brz(condition, dest, &varargs[..]);
        }
        Opcode::BrnzCfi => {
            let condition = cur.func.dfg.inst_args(forward_jump)[0];
            // let new_label = cur.func.dfg.inst_args(forward_jump)[1];
            cur.ins().brnz(condition, dest, &varargs[..]);
        }
        Opcode::BrifCfi => {
            let condition = match &cur.func.dfg[forward_jump] {
                InstructionData::BranchIcmp /* BranchIntCFI */ { cond, .. } => *cond,
                idata => panic!("Expected BranchIntCFI, got {:?}", idata),
            };
            let flags = cur.func.dfg.inst_args(forward_jump)[0];
            // let new_label = cur.func.dfg.inst_args(forward_jump)[1];
            cur.ins().brif(condition, flags, dest, &varargs[..]);
        }
        Opcode::BrffCfi => {
            let condition = match &cur.func.dfg[forward_jump] {
                InstructionData::BranchFloatCFI { cond, .. } => *cond,
                idata => panic!("Expected BranchFloatCFI, got {:?}", idata),
            };
            let flags = cur.func.dfg.inst_args(forward_jump)[0];
            // let new_label = cur.func.dfg.inst_args(forward_jump)[1];
            cur.ins().brff(condition, flags, dest, &varargs[..]);
        }
        _ => {
            panic!("Expected to find a CFI cond branch opcode, got {:?}", opcode);
        }
    }

    // TODO Add a cmov in the branch_exit block

    // TODO: need to change the label at the loopexit target
}

/// Add CFI top-of-block check instruction to the block.
///
/// Assumes that the cursor is current pointing at the first instruction in the
/// block.
///
/// The "top-of-block" check may not actually be placed at the very top of the
/// block; see comments inside this function.
///
/// This function MAY NOT preserve the cursor position; upon return, the cursor
/// will point to the instruction after the newly-inserted CFI check.
fn add_cfi_block_check(cur: &mut EncCursor, is_first_block: bool) {
    let block = cur.current_block().unwrap();
    let label = if is_first_block { FIRST_BLOCK_LABEL } else { cur.func.cfi_block_nums[block].unwrap() };

    // Our CFI check will clobber flags.
    // Sometimes we're not allowed to clobber flags at the top of a block.
    // It's OK to delay the CFI check until after an instruction that may need
    // the flags, as long as we don't move the CFI check past:
    //   - an instruction that could read or write memory
    //   - an instruction that could branch or call
    //   - an instruction that _writes_ flags (as then we would clobber them)
    //   - an instruction that writes r14: `SetCfiLabel` or `JumpTableEntryCfi`
    //   - an instruction that needs its own CFI check
    //
    // The current implementation here simply delays the CFI check as long as possible
    // given the above constraints.
    loop {
        let inst = cur.current_inst().expect("Reached the end of the block without finding any branch or jump instruction?");
        let opcode = cur.func.dfg[inst].opcode();
        if opcode.can_load() || opcode.can_store() {
            break;
        }
        if opcode.is_branch() || opcode.is_indirect_branch() || opcode.is_call() {
            break;
        }
        if opcode.writes_cpu_flags() {
            break;
        }
        if opcode == Opcode::SetCfiLabel || opcode == Opcode::JumpTableEntryCfi {
            break;
        }
        if needs_cfi_inst_check(cur, inst) {
            break;
        }

        // Additionally, if it's an unconditional trap, we do the CFI check before the trap
        if opcode == Opcode::Trap {
            break;
        }

        // safe to delay the CFI check past this instruction
        cur.next_inst();
    }

    let label = cur.ins().iconst(types::I64, label as i64);
    cur.ins().cfi_check_that_label_is_equal_to(label);
}

/// Does the current instruction need a CFI "top-of-block" check instruction despite
/// being in the middle of the block?
///
/// This is true for call instructions and some conditional branch instructions;
/// it's obviously not true for any terminators.
///
/// This function preserves the cursor position.
fn needs_cfi_inst_check(cur: &mut EncCursor, inst: Inst) -> bool {
    let opcode = cur.func.dfg[inst].opcode();
    if opcode.is_terminator() {
        false
    } else if opcode.is_call() {
        true
    } else if opcode.is_branch() || opcode.is_indirect_branch() {
        is_followed_by_non_jump_or_fallthrough(cur)
    } else {
        false
    }
}

/// Add CFI "top-of-block" check instruction for "blocks" which are only parts of
/// Cranelift blocks.
///
/// This function should only be called on an instruction which needs it,
/// according to `needs_cfi_inst_check()`.
///
/// This function preserves the cursor position.
fn add_cfi_inst_check(cur: &mut EncCursor, inst: Inst) {
    let saved_position = cur.position();
    debug_assert!(needs_cfi_inst_check(cur, inst));
    let label = cur.func.cfi_inst_nums[inst].unwrap();
    cur.next_inst(); // we want to insert _after_ the call or condbr
    let label = cur.ins().iconst(types::I64, label as i64);
    cur.ins().cfi_check_that_label_is_equal_to(label);
    cur.set_position(saved_position);
}

/*
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
*/

/*
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

    // cfi_label_inst may be CondbrGetNewCfiLabel or SetCfiLabel
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
*/

/*
/// Put in the correct real CFI numbers for jump tables.
fn set_labels_for_jumptablebr(func: &mut Function) {
    // TODO: for now we just ensure that the jump table entries all contain constant FIXED_LABEL
    for (jt, jtdata) in func.jump_tables.iter() {
        for &(block, label) in jtdata.iter() {
            if label != (FIXED_LABEL as u32) {
                panic!("Incorrect jump table entry label: found label {} for block {} in jump table {:?}", label, block, jt);
            }
        }
    }
}
*/

/*
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
*/

/*
/// Get previous inst with opcode == SetCfiLabel
/// If the previous instruction is a conditional branch this won't exist
///
/// This function preserves the cursor position.
fn get_previous_set_cfi_label_inst(cur: &mut EncCursor) -> Option<Inst> {
    let saved_cursor_position = cur.position();

    let found = loop {
        cur.prev_inst();
        match cur.current_inst() {
            None => break None,
            Some(cur_inst) => {
                match cur.func.dfg[cur_inst].opcode() {
                    Opcode::SetCfiLabel => {
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
*/

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

/// "Peeks" the opcode of the next instruction without actually moving the cursor
fn get_next_opcode(cur: &mut EncCursor) -> Option<Opcode> {
    get_next_inst(cur).map(|inst| cur.func.dfg[inst].opcode())
}

/// "Peeks" the opcode of the prev instruction without actually moving the cursor
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
        let ret = in_regs.by_ref().any(|r| r == r15)
            || !is_stack_op(isa, opcode, in_regs);
        return ret;
    } else {
        false
    }
}

fn is_stack_op(isa: &dyn TargetIsa, opcode: Opcode, mut in_regs: impl Iterator<Item = RegUnit>) -> bool {
    let rsp = isa.register_info().parse_regunit("rsp").unwrap();
    if opcode.can_load() || opcode.can_store() {
        let stack_op = opcode == Opcode::X86Push
            || opcode == Opcode::X86Pop
            || opcode == Opcode::Spill
            || opcode == Opcode::Fill
            || opcode == Opcode::Regspill
            || opcode == Opcode::Regfill
            || in_regs.any(|r| r == rsp);
        return stack_op;
    } else {
        false
    }
}

/// Is there a heap operation in the given `Block`?
///
/// It doesn't matter where `cur` is pointing - it doesn't have to be pointing at
/// `block` when calling this function. But `divert` should be for the
/// appropriate `Block`.
///
/// This function preserves the cursor position.
fn is_heap_op_in_block(cur: &mut EncCursor, block: Block, isa: &dyn TargetIsa, divert: &RegDiversions) -> bool {
    let saved_position = cur.position();
    cur.goto_first_inst(block);
    let found_heap_op = loop {
        match cur.current_inst() {
            None => break false, // done with all instructions in block
            Some(inst) => {
                let opcode = cur.func.dfg[inst].opcode();
                let args = cur.func.dfg.inst_args(inst).iter().copied();
                let in_regs = get_registers(&cur.func, &divert, args);
                if is_heap_op(isa, opcode, in_regs) {
                    break true;
                }
            }
        }
        cur.next_inst();
    };
    cur.set_position(saved_position);
    return found_heap_op;
}

/// This function preserves the cursor position.
fn is_followed_by_non_jump_or_fallthrough(cur: &mut EncCursor) -> bool {
    match get_next_opcode(cur) {
        Some(Opcode::Jump) | Some(Opcode::Fallthrough) => false,
        None => panic!("is_followed_by_non_jump_or_fallthrough: this is the last instruction in block"), // caller should not call this with a terminator
        _ => true,
    }
}

/// Is there a call or non-terminator branch in the given `Block`?
///
/// It doesn't matter where `cur` is pointing - it doesn't have to be pointing at
/// `block` when calling this function.
///
/// This function preserves the cursor position.
fn is_call_or_non_term_branch_in_block(cur: &mut EncCursor, block: Block) -> bool {
    let saved_position = cur.position();
    cur.goto_first_inst(block);
    let found = loop {
        match cur.current_inst() {
            None => break false, // done with all instructions in block
            Some(inst) => {
                let opcode = cur.func.dfg[inst].opcode();
                if !opcode.is_terminator()
                    && (opcode.is_call() || opcode.is_branch() || opcode.is_indirect_branch())
                {
                    break true;
                }
            }
        }
        cur.next_inst();
    };
    cur.set_position(saved_position);
    return found;
}
