//! Intermediate representation of a function.
//!
//! The `Function` struct defined in this module owns all of its basic blocks and
//! instructions.

use crate::binemit::CodeOffset;
use crate::entity::{PrimaryMap, SecondaryMap};
use crate::ir;
use crate::ir::{
    Block, ExtFuncData, FuncRef, GlobalValue, GlobalValueData, Heap, HeapData, Inst, JumpTable,
    JumpTableData, Opcode, SigRef, StackSlot, StackSlotData, Table, TableData,
};
use crate::ir::{BlockOffsets, InstEncodings, SourceLocs, StackSlots, ValueLocations};
use crate::ir::{DataFlowGraph, ExternalName, Layout, Signature};
use crate::ir::{JumpTableOffsets, JumpTables};
use crate::isa::{CallConv, EncInfo, Encoding, Legalize, TargetIsa};
use crate::regalloc::{EntryRegDiversions, RegDiversions};
use crate::value_label::ValueLabelsRanges;
use crate::write::write_function;
use alloc::vec::Vec;
use core::fmt;

/// A function.
///
/// Functions can be cloned, but it is not a very fast operation.
/// The clone will have all the same entity numbers as the original.
#[derive(Clone)]
pub struct Function {
    /// Name of this function. Mostly used by `.clif` files.
    pub name: ExternalName,

    /// Signature of this function.
    pub signature: Signature,

    /// The old signature of this function, before the most recent legalization,
    /// if any.
    pub old_signature: Option<Signature>,

    /// Stack slots allocated in this function.
    pub stack_slots: StackSlots,

    /// Global values referenced.
    pub global_values: PrimaryMap<ir::GlobalValue, ir::GlobalValueData>,

    /// Heaps referenced.
    pub heaps: PrimaryMap<ir::Heap, ir::HeapData>,

    /// Tables referenced.
    pub tables: PrimaryMap<ir::Table, ir::TableData>,

    /// Jump tables used in this function.
    pub jump_tables: JumpTables,

    /// Data flow graph containing the primary definition of all instructions, blocks and values.
    pub dfg: DataFlowGraph,

    /// Layout of blocks and instructions in the function body.
    pub layout: Layout,

    /// Encoding recipe and bits for the legal instructions.
    /// Illegal instructions have the `Encoding::default()` value.
    pub encodings: InstEncodings,

    /// Used for spectre resistance. Whether to use lfence before the instruction.
    pub pre_lfence: SecondaryMap<Inst, bool>,

    /// Used for spectre resistance. Whether to use lfence after the instruction.
    pub post_lfence: SecondaryMap<Inst, bool>,

    /// Used for spectre resistance. Whether to use lfence at the start of the block.
    pub block_lfence: SecondaryMap<Block, bool>,

    /// Used for spectre resistance. Whether to use endbranch before the instruction.
    pub pre_endbranch: SecondaryMap<Inst, bool>,

    /// Used for spectre resistance. Whether to use endbranch at the start of the block.
    pub block_endbranch: SecondaryMap<Block, bool>,

    /// Used for spectre resistance. Whether to replace this instruction.
    /// If vec length is > 0, instruction is replaced with bytes in vec.
    pub replacement: SecondaryMap<Inst, Vec<u8>>,

    /// Used for spectre resistance. Whether this return is replaced with pop,jmp.
    pub call_ret_replaced: SecondaryMap<Inst, bool>,

    /// Used for spectre resistance. Set of registers to truncate to 32-bits before using the instruction.
    pub registers_to_truncate: SecondaryMap<Inst, Vec<u16>>,

    /// Avoid bounds checks for these jump tables. Used the pht to btb conversion which converts direct branches to switch tables
    pub brtable_no_bounds_check: SecondaryMap<Inst, bool>,

    /// Used for spectre resistance. What instructions to use to guard a linear block.
    pub block_guards: SecondaryMap<Block, Vec<u8>>,

    /// Used for spectre resistance. What instructions to use to guard an instruction.
    pub pre_inst_guards: SecondaryMap<Inst, Vec<u8>>,

    /// Used for spectre resistance. What instructions to use to guard after the instruction.
    pub post_inst_guards: SecondaryMap<Inst, Vec<u8>>,

    /// Used for spectre resistance. What is the unique cfi label of this linear block
    pub cfi_block_nums: SecondaryMap<Block, Option<u64>>,

    /// Used for spectre resistance. What is the unique cfi label of this linear block.
    /// Some instructions mark the beginning of linear blocks
    pub cfi_inst_nums: SecondaryMap<Inst, Option<u64>>,

    /// Location assigned to every value.
    pub locations: ValueLocations,

    /// Non-default locations assigned to value at the entry of basic blocks.
    ///
    /// At the entry of each basic block, we might have values which are not in their default
    /// ValueLocation. This field records these register-to-register moves as Diversions.
    pub entry_diversions: EntryRegDiversions,

    /// Code offsets of the block headers.
    ///
    /// This information is only transiently available after the `binemit::relax_branches` function
    /// computes it, and it can easily be recomputed by calling that function. It is not included
    /// in the textual IR format.
    pub offsets: BlockOffsets,

    /// Code offsets of Jump Table headers.
    pub jt_offsets: JumpTableOffsets,

    /// Source locations.
    ///
    /// Track the original source location for each instruction. The source locations are not
    /// interpreted by Cranelift, only preserved.
    pub srclocs: SourceLocs,

    /// Instruction that marks the end (inclusive) of the function's prologue.
    ///
    /// This is used for some ABIs to generate unwind information.
    pub prologue_end: Option<Inst>,

    /// The instructions that mark the start (inclusive) of an epilogue in the function.
    ///
    /// This is used for some ABIs to generate unwind information.
    pub epilogues_start: Vec<Inst>,

    /// An optional global value which represents an expression evaluating to
    /// the stack limit for this function. This `GlobalValue` will be
    /// interpreted in the prologue, if necessary, to insert a stack check to
    /// ensure that a trap happens if the stack pointer goes below the
    /// threshold specified here.
    pub stack_limit: Option<ir::GlobalValue>,
}

impl Function {
    /// Create a function with the given name and signature.
    pub fn with_name_signature(name: ExternalName, sig: Signature) -> Self {
        Self {
            name,
            signature: sig,
            old_signature: None,
            stack_slots: StackSlots::new(),
            global_values: PrimaryMap::new(),
            heaps: PrimaryMap::new(),
            tables: PrimaryMap::new(),
            jump_tables: PrimaryMap::new(),
            dfg: DataFlowGraph::new(),
            layout: Layout::new(),
            encodings: SecondaryMap::new(),
            pre_lfence: SecondaryMap::new(),
            post_lfence: SecondaryMap::new(),
            block_lfence: SecondaryMap::new(),
            pre_endbranch: SecondaryMap::new(),
            block_endbranch: SecondaryMap::new(),
            replacement: SecondaryMap::new(),
            call_ret_replaced: SecondaryMap::new(),
            registers_to_truncate: SecondaryMap::new(),
            brtable_no_bounds_check: SecondaryMap::new(),
            block_guards: SecondaryMap::new(),
            pre_inst_guards: SecondaryMap::new(),
            post_inst_guards: SecondaryMap::new(),
            cfi_block_nums: SecondaryMap::new(),
            cfi_inst_nums: SecondaryMap::new(),
            locations: SecondaryMap::new(),
            entry_diversions: EntryRegDiversions::new(),
            offsets: SecondaryMap::new(),
            jt_offsets: SecondaryMap::new(),
            srclocs: SecondaryMap::new(),
            prologue_end: None,
            epilogues_start: Vec::new(),
            stack_limit: None,
        }
    }

    /// Clear all data structures in this function.
    pub fn clear(&mut self) {
        self.signature.clear(CallConv::Fast);
        self.stack_slots.clear();
        self.global_values.clear();
        self.heaps.clear();
        self.tables.clear();
        self.jump_tables.clear();
        self.dfg.clear();
        self.layout.clear();
        self.encodings.clear();
        self.pre_lfence.clear();
        self.post_lfence.clear();
        self.block_lfence.clear();
        self.pre_endbranch.clear();
        self.block_endbranch.clear();
        self.replacement.clear();
        self.call_ret_replaced.clear();
        self.registers_to_truncate.clear();
        self.brtable_no_bounds_check.clear();
        self.block_guards.clear();
        self.pre_inst_guards.clear();
        self.post_inst_guards.clear();
        self.cfi_block_nums.clear();
        self.cfi_inst_nums.clear();
        self.locations.clear();
        self.entry_diversions.clear();
        self.offsets.clear();
        self.jt_offsets.clear();
        self.srclocs.clear();
        self.prologue_end = None;
        self.epilogues_start.clear();
        self.stack_limit = None;
    }

    /// Create a new empty, anonymous function with a Fast calling convention.
    pub fn new() -> Self {
        Self::with_name_signature(ExternalName::default(), Signature::new(CallConv::Fast))
    }

    /// Creates a jump table in the function, to be used by `br_table` instructions.
    pub fn create_jump_table(&mut self, data: JumpTableData) -> JumpTable {
        self.jump_tables.push(data)
    }

    /// Creates a stack slot in the function, to be used by `stack_load`, `stack_store` and
    /// `stack_addr` instructions.
    pub fn create_stack_slot(&mut self, data: StackSlotData) -> StackSlot {
        self.stack_slots.push(data)
    }

    /// Adds a signature which can later be used to declare an external function import.
    pub fn import_signature(&mut self, signature: Signature) -> SigRef {
        self.dfg.signatures.push(signature)
    }

    /// Declare an external function import.
    pub fn import_function(&mut self, data: ExtFuncData) -> FuncRef {
        self.dfg.ext_funcs.push(data)
    }

    /// Declares a global value accessible to the function.
    pub fn create_global_value(&mut self, data: GlobalValueData) -> GlobalValue {
        self.global_values.push(data)
    }

    /// Declares a heap accessible to the function.
    pub fn create_heap(&mut self, data: HeapData) -> Heap {
        self.heaps.push(data)
    }

    /// Declares a table accessible to the function.
    pub fn create_table(&mut self, data: TableData) -> Table {
        self.tables.push(data)
    }

    /// Return an object that can display this function with correct ISA-specific annotations.
    pub fn display<'a, I: Into<Option<&'a dyn TargetIsa>>>(
        &'a self,
        isa: I,
    ) -> DisplayFunction<'a> {
        DisplayFunction(self, isa.into().into())
    }

    /// Return an object that can display this function with correct ISA-specific annotations.
    pub fn display_with<'a>(
        &'a self,
        annotations: DisplayFunctionAnnotations<'a>,
    ) -> DisplayFunction<'a> {
        DisplayFunction(self, annotations)
    }

    /// Find a presumed unique special-purpose function parameter value.
    ///
    /// Returns the value of the last `purpose` parameter, or `None` if no such parameter exists.
    pub fn special_param(&self, purpose: ir::ArgumentPurpose) -> Option<ir::Value> {
        let entry = self.layout.entry_block().expect("Function is empty");
        self.signature
            .special_param_index(purpose)
            .map(|i| self.dfg.block_params(entry)[i])
    }

    /// Get an iterator over the instructions in `block`, including offsets and encoded instruction
    /// sizes.
    ///
    /// The iterator returns `(offset, inst, size)` tuples, where `offset` if the offset in bytes
    /// from the beginning of the function to the instruction, and `size` is the size of the
    /// instruction in bytes, or 0 for unencoded instructions.
    ///
    /// This function can only be used after the code layout has been computed by the
    /// `binemit::relax_branches()` function.
    pub fn inst_offsets<'a>(&'a self, block: Block, encinfo: &EncInfo) -> InstOffsetIter<'a> {
        assert!(
            !self.offsets.is_empty(),
            "Code layout must be computed first"
        );
        let mut divert = RegDiversions::new();
        divert.at_block(&self.entry_diversions, block);
        InstOffsetIter {
            encinfo: encinfo.clone(),
            func: self,
            divert,
            encodings: &self.encodings,
            offset: self.offsets[block],
            iter: self.layout.block_insts(block),
        }
    }

    /// Wrapper around `encode` which assigns `inst` the resulting encoding.
    pub fn update_encoding(&mut self, inst: ir::Inst, isa: &dyn TargetIsa) -> Result<(), Legalize> {
        if isa.get_mach_backend().is_some() {
            Ok(())
        } else {
            self.encode(inst, isa).map(|e| self.encodings[inst] = e)
        }
    }

    /// Wrapper around `TargetIsa::encode` for encoding an existing instruction
    /// in the `Function`.
    pub fn encode(&self, inst: ir::Inst, isa: &dyn TargetIsa) -> Result<Encoding, Legalize> {
        if isa.get_mach_backend().is_some() {
            Ok(Encoding::new(0, 0))
        } else {
            isa.encode(&self, &self.dfg[inst], self.dfg.ctrl_typevar(inst))
        }
    }

    /// Starts collection of debug information.
    pub fn collect_debug_info(&mut self) {
        self.dfg.collect_debug_info();
    }

    /// Changes the destination of a jump or branch instruction.
    /// Does nothing if called with a non-jump or non-branch instruction.
    pub fn change_branch_destination(&mut self, inst: Inst, new_dest: Block) {
        match self.dfg[inst].branch_destination_mut() {
            None => (),
            Some(inst_dest) => *inst_dest = new_dest,
        }
    }

    /// Checks that the specified block can be encoded as a basic block.
    ///
    /// On error, returns the first invalid instruction and an error message.
    pub fn is_block_basic(&self, block: Block) -> Result<(), (Inst, std::string::String)> {
        let dfg = &self.dfg;
        let inst_iter = self.layout.block_insts(block);

        // Ignore all instructions prior to the first branch.
        let mut inst_iter = inst_iter.skip_while(|&inst| !dfg[inst].opcode().is_branch());

        // A conditional branch is permitted in a basic block only when followed
        // by a terminal jump or fallthrough instruction.
        if let Some(branch) = inst_iter.next() {
            if let Some(next) = inst_iter.next() {
                match dfg[next].opcode() {
                    Opcode::Fallthrough | Opcode::Jump => (),
                    opcode => return Err((next, format!("post-branch instruction not fallthrough or jump. Branch opcode was {}, post-branch opcode was {}", dfg[branch].opcode(), opcode))),
                }
            }
        }

        Ok(())
    }

    /// Returns true if the function is function that doesn't call any other functions. This is not
    /// to be confused with a "leaf function" in Windows terminology.
    pub fn is_leaf(&self) -> bool {
        // Conservative result: if there's at least one function signature referenced in this
        // function, assume it is not a leaf.
        self.dfg.signatures.is_empty()
    }
}

/// Additional annotations for function display.
#[derive(Default)]
pub struct DisplayFunctionAnnotations<'a> {
    /// Enable ISA annotations.
    pub isa: Option<&'a dyn TargetIsa>,

    /// Enable value labels annotations.
    pub value_ranges: Option<&'a ValueLabelsRanges>,
}

impl<'a> From<Option<&'a dyn TargetIsa>> for DisplayFunctionAnnotations<'a> {
    fn from(isa: Option<&'a dyn TargetIsa>) -> DisplayFunctionAnnotations {
        DisplayFunctionAnnotations {
            isa,
            value_ranges: None,
        }
    }
}

/// Wrapper type capable of displaying a `Function` with correct ISA annotations.
pub struct DisplayFunction<'a>(&'a Function, DisplayFunctionAnnotations<'a>);

impl<'a> fmt::Display for DisplayFunction<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write_function(fmt, self.0, &self.1)
    }
}

impl fmt::Display for Function {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write_function(fmt, self, &DisplayFunctionAnnotations::default())
    }
}

impl fmt::Debug for Function {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write_function(fmt, self, &DisplayFunctionAnnotations::default())
    }
}

/// Iterator returning instruction offsets and sizes: `(offset, inst, size)`.
pub struct InstOffsetIter<'a> {
    encinfo: EncInfo,
    divert: RegDiversions,
    func: &'a Function,
    encodings: &'a InstEncodings,
    offset: CodeOffset,
    iter: ir::layout::Insts<'a>,
}

impl<'a> Iterator for InstOffsetIter<'a> {
    type Item = (CodeOffset, ir::Inst, CodeOffset);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|inst| {
            self.divert.apply(&self.func.dfg[inst]);
            let byte_size =
                self.encinfo
                    .byte_size(self.encodings[inst], inst, &self.divert, self.func);
            let offset = self.offset;
            self.offset += byte_size;
            (offset, inst, byte_size)
        })
    }
}
