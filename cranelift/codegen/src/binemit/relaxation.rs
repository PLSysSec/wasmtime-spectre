//! Branch relaxation and offset computation.
//!
//! # block header offsets
//!
//! Before we can generate binary machine code for branch instructions, we need to know the final
//! offsets of all the block headers in the function. This information is encoded in the
//! `func.offsets` table.
//!
//! # Branch relaxation
//!
//! Branch relaxation is the process of ensuring that all branches in the function have enough
//! range to encode their destination. It is common to have multiple branch encodings in an ISA.
//! For example, x86 branches can have either an 8-bit or a 32-bit displacement.
//!
//! On RISC architectures, it can happen that conditional branches have a shorter range than
//! unconditional branches:
//!
//! ```clif
//!     brz v1, block17
//! ```
//!
//! can be transformed into:
//!
//! ```clif
//!     brnz v1, block23
//!     jump block17
//! block23:
//! ```

use crate::binemit::{CodeInfo, CodeOffset};
use crate::cursor::{Cursor, FuncCursor};
use crate::dominator_tree::DominatorTree;
use crate::flowgraph::ControlFlowGraph;
use crate::ir::{Block, Function, Inst, InstructionData, Opcode, Value, ValueList, ValueLoc};
use crate::isa::{registers::RegUnit, EncInfo, TargetIsa};
use crate::iterators::IteratorExtras;
use crate::regalloc::RegDiversions;
use crate::timing;
use crate::CodegenResult;
use core::convert::TryFrom;
use log::debug;
use std::vec::Vec;

#[cfg(feature = "basic-blocks")]
use crate::ir::{Ebb, Inst, Value, ValueList};

use cranelift_spectre::settings::{
    get_spectre_mitigation, SpectreMitigation,
};

fn spectre_resistance_on_func(
    _isa: &dyn TargetIsa,
    cur: &mut FuncCursor,
    first_inst: &Inst,
    _divert: &RegDiversions,
    can_be_indirectly_called: bool,
) {
    let mitigation = get_spectre_mitigation();
    if mitigation == SpectreMitigation::CET {
        cur.func.pre_endbranch[*first_inst] = true;
        if can_be_indirectly_called {
            cur.func.pre_lfence[*first_inst] = true;
        }
    }
}

fn spectre_resistance_on_basic_block(_isa: &dyn TargetIsa, cur: &mut FuncCursor, first_inst: &Inst, _divert: &RegDiversions, _is_first_block: bool) {
    let mitigation = get_spectre_mitigation();

    if mitigation == SpectreMitigation::STRAWMAN {
        cur.func.pre_lfence[*first_inst] = true;
    }
}

fn spectre_resistance_on_inst(
    isa: &dyn TargetIsa,
    cur: &mut FuncCursor,
    inst: &Inst,
    divert: &RegDiversions,
) {
    let opcode = cur.func.dfg[*inst].opcode();
    let _format = opcode.format();
    let mitigation = get_spectre_mitigation();

    match mitigation {
        SpectreMitigation::STRAWMAN => {
            // Strawman wants to add lfence to the beginning of every basic block, i.e. branch
            // target. In addition to the beginning of every EBB (done above), we need to add
            // lfence inside an EBB after every call (bc that's a return target) and after
            // every conditional branch (bc that's a fallthrough target).
            // Note that in Cranelift, conditional branches and calls do not end blocks (EBBs),
            // while unconditional branches, rets, etc do end EBBs.
            if !opcode.is_terminator()
                && (opcode.is_call() || opcode.is_branch() || opcode.is_indirect_branch())
            {
                cur.func.post_lfence[*inst] = true;
            }
        }
        SpectreMitigation::LOADLFENCE => {
            if opcode.can_load() {
                cur.func.post_lfence[*inst] = true;
            }
        }
        SpectreMitigation::SFI => {
            if opcode.is_return() && !cur.func.ret_replaced[*inst] {
                let replacement = cranelift_spectre::inst::get_pop_jump_ret();
                cur.func.replacement[*inst].append(&mut replacement.to_vec());
                cur.func.ret_replaced[*inst] = true;
            }

            let heap_index_registers = get_pinned_base_heap_index_registers(isa, cur, divert, inst);
            cur.func.registers_to_truncate[*inst] = heap_index_registers;
        }
        _ => {}
    }
}

fn get_registers(cur: &FuncCursor, divert: &RegDiversions, values: &[Value]) -> Vec<RegUnit> {
    let mut regs = vec![];
    for value in values {
        let v = divert.get(*value, &cur.func.locations);
        match v {
            ValueLoc::Reg(r) => regs.push(r),
            _ => (),
        };
    }
    regs
}

fn is_heap_op(isa: &dyn TargetIsa, func: &Function, in_regs: &[RegUnit], inst: Inst) -> bool {
    let opcode = func.dfg[inst].opcode();
    let r15 = isa.register_info().parse_regunit("r15").unwrap();
    if opcode.can_load() || opcode.can_store() &&
        !(opcode == Opcode::X86Push
        || opcode == Opcode::X86Pop
        || opcode == Opcode::Spill
        || opcode == Opcode::Fill
        || opcode == Opcode::Regspill
        || opcode == Opcode::Regfill) {
        in_regs.iter().any(|&r| r == r15)
    } else {
        false
    }
}

fn get_pinned_base_heap_index_registers(
    isa: &dyn TargetIsa,
    cur: &FuncCursor,
    divert: &RegDiversions,
    inst: &Inst,
) -> Vec<u16> {
    let _rets = cur.func.dfg.inst_results(*inst);
    let _out_regs = get_registers(&cur, &divert, _rets);

    let args = cur.func.dfg.inst_args(*inst);
    let in_regs = get_registers(&cur, &divert, args);

    let get_heap_index_regs = |in_regs: &[RegUnit]| {
        // for now, we just pick the last arg as all inst seems to have the format
        // loaded_val = load(r_heapbase, r_index)
        // store(stored_val, r_heapbase, r_index)
        vec![in_regs.last().unwrap().clone()]
    };

    let regs = if is_heap_op(isa, &cur.func, &in_regs, *inst) {
        get_heap_index_regs(&in_regs)
    } else {
        vec![]
    };

    return regs;
}

/// Relax branches and compute the final layout of block headers in `func`.
///
/// Fill in the `func.offsets` table so the function is ready for binary emission.
pub fn relax_branches(
    func: &mut Function,
    _cfg: &mut ControlFlowGraph,
    _domtree: &mut DominatorTree,
    isa: &dyn TargetIsa,
    can_be_indirectly_called: bool,
) -> CodegenResult<CodeInfo> {
    let _tt = timing::relax_branches();
    let _reg = isa.register_info().parse_regunit("r15");

    let encinfo = isa.encoding_info();

    // Clear all offsets so we can recognize blocks that haven't been visited yet.
    func.offsets.clear();
    func.offsets.resize(func.dfg.num_blocks());

    // Start by removing redundant jumps.
    fold_redundant_jumps(func, _cfg, _domtree);

    // Convert jumps to fallthrough instructions where possible.
    fallthroughs(func);

    let mut offset = 0;
    let mut divert = RegDiversions::new();

    // First, compute initial offsets for every block.
    {
        let mut cur = FuncCursor::new(func);
        while let Some(block) = cur.next_block() {
            divert.at_block(&cur.func.entry_diversions, block);
            cur.func.offsets[block] = offset;
            while let Some(inst) = cur.next_inst() {
                divert.apply(&cur.func.dfg[inst]);
                let enc = cur.func.encodings[inst];
                offset += encinfo.byte_size(enc, inst, &divert, &cur.func);
            }
        }
    }

    // Then, run the relaxation algorithm until it converges.
    let mut go_again = true;
    while go_again {
        go_again = false;
        offset = 0;

        let mut _inst_num = 0;
        let mut first_inst_in_func = true;
        let mut first_inst_in_block;

        // Visit all instructions in layout order.
        let mut cur = FuncCursor::new(func);
        while let Some(block) = cur.next_block() {
            divert.at_block(&cur.func.entry_diversions, block);

            // Record the offset for `block` and make sure we iterate until offsets are stable.
            if cur.func.offsets[block] != offset {
                cur.func.offsets[block] = offset;
                go_again = true;
            }

            first_inst_in_block = true;

            while let Some(inst) = cur.next_inst() {
                _inst_num = _inst_num + 1;

                divert.apply(&cur.func.dfg[inst]);

                let enc = cur.func.encodings[inst];

                if first_inst_in_func {
                    spectre_resistance_on_func(isa, &mut cur, &inst, &divert, can_be_indirectly_called);
                }
                if first_inst_in_block {
                    spectre_resistance_on_basic_block(isa, &mut cur, &inst, &divert, first_inst_in_func);
                }

                spectre_resistance_on_inst(isa, &mut cur, &inst, &divert);

                let reg_clear_bytes_size: usize = cur.func.registers_to_truncate[inst]
                    .iter()
                    .map(|&reg| cranelift_spectre::inst::get_reg_truncate_bytes(reg).len())
                    .sum();

                let pre_insert_size = if cur.func.pre_lfence[inst] {
                    cranelift_spectre::inst::get_lfence().len() as u32
                } else {
                    0
                } + if cur.func.pre_endbranch[inst] {
                    cranelift_spectre::inst::get_endbranch().len() as u32
                } else {
                    0
                } + (cur.func.pre_inst_guards[inst].len() as u32)
                    + (reg_clear_bytes_size as u32)
                    + if first_inst_in_block {
                        let block_inserts = if cur.func.block_lfence[block] {
                            cranelift_spectre::inst::get_lfence().len() as u32
                        } else {
                            0
                        } + if cur.func.block_endbranch[block] {
                            cranelift_spectre::inst::get_endbranch().len() as u32
                        } else {
                            0
                        } + cur.func.block_guards[block].len() as u32;
                        block_inserts
                    } else {
                        0
                    };
                offset += pre_insert_size;

                // See if this is a branch has a range and a destination, and if the target is in
                // range.
                if let Some(range) = encinfo.branch_range(enc) {
                    if let Some(dest) = cur.func.dfg[inst].branch_destination() {
                        let dest_offset = cur.func.offsets[dest];
                        if !range.contains(offset, dest_offset) {
                            relax_branch(&mut cur, &divert, offset, dest_offset, &encinfo, isa);
                        }
                    }
                }

                // get enc again as it may be updated in relax_branch
                let enc = cur.func.encodings[inst];
                let inst_size = encinfo.byte_size(enc, inst, &divert, &cur.func);
                let post_insert_size = if cur.func.post_lfence[inst] {
                    cranelift_spectre::inst::get_lfence().len() as u32
                } else {
                    0
                } + (cur.func.post_inst_guards[inst].len() as u32);
                offset += inst_size + post_insert_size;
                first_inst_in_block = false;
                first_inst_in_func = false;
            }
        }
    }

    let code_size = offset;
    let jumptables = offset;

    for (jt, jt_data) in func.jump_tables.iter() {
        func.jt_offsets[jt] = offset;
        // TODO: this should be computed based on the min size needed to hold the furthest branch.
        offset += jt_data.len() as u32 * 4;
    }

    let jumptables_size = offset - jumptables;
    let rodata = offset;

    for constant in func.dfg.constants.entries_mut() {
        constant.set_offset(offset);
        offset +=
            u32::try_from(constant.len()).expect("Constants must have a length that fits in a u32")
    }

    let rodata_size = offset - rodata;

    Ok(CodeInfo {
        code_size,
        jumptables_size,
        rodata_size,
        total_size: offset,
    })
}

/// Folds an instruction if it is a redundant jump.
/// Returns whether folding was performed (which invalidates the CFG).
fn try_fold_redundant_jump(
    func: &mut Function,
    cfg: &mut ControlFlowGraph,
    block: Block,
    first_inst: Inst,
) -> bool {
    let first_dest = match func.dfg[first_inst].branch_destination() {
        Some(block) => block, // The instruction was a single-target branch.
        None => {
            return false; // The instruction was either multi-target or not a branch.
        }
    };

    // For the moment, only attempt to fold a branch to a block that is parameterless.
    // These blocks are mainly produced by critical edge splitting.
    //
    // TODO: Allow folding blocks that define SSA values and function as phi nodes.
    if func.dfg.num_block_params(first_dest) != 0 {
        return false;
    }

    // Look at the first instruction of the first branch's destination.
    // If it is an unconditional branch, maybe the second jump can be bypassed.
    let second_inst = func.layout.first_inst(first_dest).expect("Instructions");
    if func.dfg[second_inst].opcode() != Opcode::Jump {
        return false;
    }

    // Now we need to fix up first_inst's block parameters to match second_inst's,
    // without changing the branch-specific arguments.
    //
    // The intermediary block is allowed to reference any SSA value that dominates it,
    // but that SSA value may not necessarily also dominate the instruction that's
    // being patched.

    // Get the arguments and parameters passed by the first branch.
    let num_fixed = func.dfg[first_inst]
        .opcode()
        .constraints()
        .num_fixed_value_arguments();
    let (first_args, first_params) = func.dfg[first_inst]
        .arguments(&func.dfg.value_lists)
        .split_at(num_fixed);

    // Get the parameters passed by the second jump.
    let num_fixed = func.dfg[second_inst]
        .opcode()
        .constraints()
        .num_fixed_value_arguments();
    let (_, second_params) = func.dfg[second_inst]
        .arguments(&func.dfg.value_lists)
        .split_at(num_fixed);
    let mut second_params = second_params.to_vec(); // Clone for rewriting below.

    // For each parameter passed by the second jump, if any of those parameters
    // was a block parameter, rewrite it to refer to the value that the first jump
    // passed in its parameters. Otherwise, make sure it dominates first_inst.
    //
    // For example: if we `block0: jump block1(v1)` to `block1(v2): jump block2(v2)`,
    // we want to rewrite the original jump to `jump block2(v1)`.
    let block_params: &[Value] = func.dfg.block_params(first_dest);
    debug_assert!(block_params.len() == first_params.len());

    for value in second_params.iter_mut() {
        if let Some((n, _)) = block_params.iter().enumerate().find(|(_, &p)| p == *value) {
            // This value was the Nth parameter passed to the second_inst's block.
            // Rewrite it as the Nth parameter passed by first_inst.
            *value = first_params[n];
        }
    }

    // Build a value list of first_args (unchanged) followed by second_params (rewritten).
    let arguments_vec: alloc::vec::Vec<_> = first_args
        .iter()
        .chain(second_params.iter())
        .copied()
        .collect();
    let value_list = ValueList::from_slice(&arguments_vec, &mut func.dfg.value_lists);

    func.dfg[first_inst].take_value_list(); // Drop the current list.
    func.dfg[first_inst].put_value_list(value_list); // Put the new list.

    // Bypass the second jump.
    // This can disconnect the Block containing `second_inst`, to be cleaned up later.
    let second_dest = func.dfg[second_inst].branch_destination().expect("Dest");
    func.change_branch_destination(first_inst, second_dest);
    cfg.recompute_block(func, block);

    // The previously-intermediary Block may now be unreachable. Update CFG.
    if cfg.pred_iter(first_dest).count() == 0 {
        // Remove all instructions from that block.
        while let Some(inst) = func.layout.first_inst(first_dest) {
            func.layout.remove_inst(inst);
        }

        // Remove the block...
        cfg.recompute_block(func, first_dest); // ...from predecessor lists.
        func.layout.remove_block(first_dest); // ...from the layout.
    }

    true
}

/// Redirects `jump` instructions that point to other `jump` instructions to the final destination.
/// This transformation may orphan some blocks.
fn fold_redundant_jumps(
    func: &mut Function,
    cfg: &mut ControlFlowGraph,
    domtree: &mut DominatorTree,
) {
    let mut folded = false;

    // Postorder iteration guarantees that a chain of jumps is visited from
    // the end of the chain to the start of the chain.
    for &block in domtree.cfg_postorder() {
        // Only proceed if the first terminator instruction is a single-target branch.
        let first_inst = func
            .layout
            .last_inst(block)
            .expect("Block has no terminator");
        folded |= try_fold_redundant_jump(func, cfg, block, first_inst);

        // Also try the previous instruction.
        if let Some(prev_inst) = func.layout.prev_inst(first_inst) {
            folded |= try_fold_redundant_jump(func, cfg, block, prev_inst);
        }
    }

    // Folding jumps invalidates the dominator tree.
    if folded {
        domtree.compute(func, cfg);
    }
}

/// Convert `jump` instructions to `fallthrough` instructions where possible and verify that any
/// existing `fallthrough` instructions are correct.
fn fallthroughs(func: &mut Function) {
    for (block, succ) in func.layout.blocks().adjacent_pairs() {
        let term = func
            .layout
            .last_inst(block)
            .expect("block has no terminator.");
        if let InstructionData::Jump {
            ref mut opcode,
            destination,
            ..
        } = func.dfg[term]
        {
            match *opcode {
                Opcode::Fallthrough => {
                    // Somebody used a fall-through instruction before the branch relaxation pass.
                    // Make sure it is correct, i.e. the destination is the layout successor.
                    debug_assert_eq!(destination, succ, "Illegal fall-through in {}", block)
                }
                Opcode::Jump => {
                    // If this is a jump to the successor block, change it to a fall-through.
                    if destination == succ {
                        *opcode = Opcode::Fallthrough;
                        func.encodings[term] = Default::default();
                    }
                }
                _ => {}
            }
        }
    }
}

/// Relax the branch instruction at `cur` so it can cover the range `offset - dest_offset`.
///
/// Return the size of the replacement instructions up to and including the location where `cur` is
/// left.
fn relax_branch(
    cur: &mut FuncCursor,
    divert: &RegDiversions,
    offset: CodeOffset,
    dest_offset: CodeOffset,
    encinfo: &EncInfo,
    isa: &dyn TargetIsa,
) -> CodeOffset {
    let inst = cur.current_inst().unwrap();
    let _opcode = cur.func.dfg[inst].opcode();
    let _format = _opcode.format();
    let _enc = cur.func.encodings[inst];

    debug!(
        "Relaxing [{}] {} for {:#x}-{:#x} range",
        encinfo.display(cur.func.encodings[inst]),
        cur.func.dfg.display_inst(inst, isa),
        offset,
        dest_offset
    );

    // Pick the smallest encoding that can handle the branch range.
    let dfg = &cur.func.dfg;
    let ctrl_type = dfg.ctrl_typevar(inst);
    if let Some(enc) = isa
        .legal_encodings(cur.func, &dfg[inst], ctrl_type)
        .filter(|&enc| {
            let range = encinfo.branch_range(enc).expect("Branch with no range");
            if !range.contains(offset, dest_offset) {
                debug!("  trying [{}]: out of range", encinfo.display(enc));
                false
            } else if encinfo.operand_constraints(enc)
                != encinfo.operand_constraints(cur.func.encodings[inst])
            {
                // Conservatively give up if the encoding has different constraints
                // than the original, so that we don't risk picking a new encoding
                // which the existing operands don't satisfy. We can't check for
                // validity directly because we don't have a RegDiversions active so
                // we don't know which registers are actually in use.
                debug!("  trying [{}]: constraints differ", encinfo.display(enc));
                false
            } else {
                debug!("  trying [{}]: OK", encinfo.display(enc));
                true
            }
        })
        .min_by_key(|&enc| encinfo.byte_size(enc, inst, &divert, &cur.func))
    {
        debug_assert!(enc != cur.func.encodings[inst]);
        cur.func.encodings[inst] = enc;
        return encinfo.byte_size(enc, inst, &divert, &cur.func);
    }

    // Note: On some RISC ISAs, conditional branches have shorter range than unconditional
    // branches, so one way of extending the range of a conditional branch is to invert its
    // condition and make it branch over an unconditional jump which has the larger range.
    //
    // Splitting the block is problematic this late because there may be register diversions in
    // effect across the conditional branch, and they can't survive the control flow edge to a new
    // block. We have two options for handling that:
    //
    // 1. Set a flag on the new block that indicates it wants the preserve the register diversions of
    //    its layout predecessor, or
    // 2. Use an encoding macro for the branch-over-jump pattern so we don't need to split the block.
    //
    // It seems that 1. would allow us to share code among RISC ISAs that need this.
    //
    // We can't allow register diversions to survive from the layout predecessor because the layout
    // predecessor could contain kill points for some values that are live in this block, and
    // diversions are not automatically cancelled when the live range of a value ends.

    // This assumes solution 2. above:
    panic!("No branch in range for {:#x}-{:#x}", offset, dest_offset);
}
