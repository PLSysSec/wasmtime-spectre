//! Legalization of global values.
//!
//! This module exports the `expand_global_value` function which transforms a `global_value`
//! instruction into code that depends on the kind of global value referenced.

use crate::cursor::{Cursor, FuncCursor};
use crate::flowgraph::ControlFlowGraph;
use crate::ir::{self, InstBuilder};
use crate::isa::TargetIsa;

/// Expand a `global_value` instruction according to the definition of the global value.
pub fn expand_global_value(
    inst: ir::Inst,
    func: &mut ir::Function,
    _cfg: &mut ControlFlowGraph,
    isa: &dyn TargetIsa,
) {
    // Unpack the instruction.
    let gv = match func.dfg[inst] {
        ir::InstructionData::UnaryGlobalValue {
            opcode,
            global_value,
        } => {
            debug_assert_eq!(opcode, ir::Opcode::GlobalValue);
            global_value
        }
        _ => panic!("Wanted global_value: {}", func.dfg.display_inst(inst, None)),
    };

    // if cranelift_spectre::inst::get_curr_func() == "guest_func___main_void" {
    //     println!("GlobalValueData:\n{}", func.display(isa));
    // }


    match func.global_values[gv] {
        ir::GlobalValueData::VMContext => vmctx_addr(inst, func),
        ir::GlobalValueData::IAddImm {
            base,
            offset,
            global_type,
        } => iadd_imm_addr(inst, func, base, offset.into(), global_type),
        ir::GlobalValueData::Load {
            base,
            offset,
            global_type,
            readonly,
        } => load_addr(inst, func, base, offset, global_type, readonly, isa),
        ir::GlobalValueData::Symbol { tls, .. } => symbol(inst, func, gv, isa, tls),
    }

    // if cranelift_spectre::inst::get_curr_func() == "guest_func___main_void" {
    //     println!("GlobalValueData:\n{}", func.display(isa));
    // }

}

/// Expand a `global_value` instruction for a vmctx global.
fn vmctx_addr(inst: ir::Inst, func: &mut ir::Function) {
    // Get the value representing the `vmctx` argument.
    let vmctx = func
        .special_param(ir::ArgumentPurpose::VMContext)
        .expect("Missing vmctx parameter");

    // Replace the `global_value` instruction's value with an alias to the vmctx arg.
    let result = func.dfg.first_result(inst);
    func.dfg.clear_results(inst);
    func.dfg.change_to_alias(result, vmctx);
    func.layout.remove_inst(inst);
}

/// Expand a `global_value` instruction for an iadd_imm global.
fn iadd_imm_addr(
    inst: ir::Inst,
    func: &mut ir::Function,
    base: ir::GlobalValue,
    offset: i64,
    global_type: ir::Type,
) {
    let mut pos = FuncCursor::new(func).at_inst(inst);

    // Get the value for the lhs. For tidiness, expand VMContext here so that we avoid
    // `vmctx_addr` which creates an otherwise unneeded value alias.
    let lhs = if let ir::GlobalValueData::VMContext = pos.func.global_values[base] {
        pos.func
            .special_param(ir::ArgumentPurpose::VMContext)
            .expect("Missing vmctx parameter")
    } else {
        pos.ins().global_value(global_type, base)
    };

    // Simply replace the `global_value` instruction with an `iadd_imm`, reusing the result value.
    pos.func.dfg.replace(inst).iadd_imm(lhs, offset);
}

/// Expand a `global_value` instruction for a load global.
fn load_addr(
    inst: ir::Inst,
    func: &mut ir::Function,
    base: ir::GlobalValue,
    curr_offset: ir::immediates::Offset32,
    global_type: ir::Type,
    readonly: bool,
    isa: &dyn TargetIsa,
) {
    let curr_offset_val : i32 = curr_offset.into();
    let offset : ir::immediates::Offset32 =
    if base == ir::GlobalValue::with_number(0).unwrap() {
            let s = cranelift_spectre::settings::get_shadow_stack_size_with_guards() as i32;
            let ret = curr_offset_val-  s;
            ir::immediates::Offset32::new(ret)
        } else {
            curr_offset
        };
    // We need to load a pointer from the `base` global value, so insert a new `global_value`
    // instruction. This depends on the iterative legalization loop. Note that the IR verifier
    // detects any cycles in the `load` globals.
    let ptr_ty = isa.pointer_type();
    let mut pos = FuncCursor::new(func).at_inst(inst);
    pos.use_srcloc(inst);

    // Get the value for the base. For tidiness, expand VMContext here so that we avoid
    // `vmctx_addr` which creates an otherwise unneeded value alias.
    let base_addr = if let ir::GlobalValueData::VMContext = pos.func.global_values[base] {
        pos.func
            .special_param(ir::ArgumentPurpose::VMContext)
            .expect("Missing vmctx parameter")
    } else {
        pos.ins().global_value(ptr_ty, base)
    };

    // Global-value loads are always notrap and aligned. They may be readonly.
    let mut mflags = ir::MemFlags::trusted();
    if readonly {
        mflags.set_readonly();
    }

    // Perform the load.
    pos.func
        .dfg
        .replace(inst)
        .load(global_type, mflags, base_addr, offset);
}

/// Expand a `global_value` instruction for a symbolic name global.
fn symbol(
    inst: ir::Inst,
    func: &mut ir::Function,
    gv: ir::GlobalValue,
    isa: &dyn TargetIsa,
    tls: bool,
) {
    let ptr_ty = isa.pointer_type();

    if tls {
        func.dfg.replace(inst).tls_value(ptr_ty, gv);
    } else {
        func.dfg.replace(inst).symbol_value(ptr_ty, gv);
    }
}
