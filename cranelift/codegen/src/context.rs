//! Cranelift compilation context and main entry point.
//!
//! When compiling many small functions, it is important to avoid repeatedly allocating and
//! deallocating the data structures needed for compilation. The `Context` struct is used to hold
//! on to memory allocations between function compilations.
//!
//! The context does not hold a `TargetIsa` instance which has to be provided as an argument
//! instead. This is because an ISA instance is immutable and can be used by multiple compilation
//! contexts concurrently. Typically, you would have one context per compilation thread and only a
//! single ISA instance.

use crate::binemit::{
    relax_branches, shrink_instructions, CodeInfo, MemoryCodeSink, RelocSink, StackmapSink,
    TrapSink,
};
use crate::blade::do_blade;
use crate::cfi::{do_br_cfi, do_cfi_add_checks, do_cfi_number_allocate, do_cfi_set_correct_labels, do_condbr_cfi, do_indirectbr_cfi};
use crate::dce::do_dce;
use crate::dominator_tree::DominatorTree;
use crate::flowgraph::ControlFlowGraph;
use crate::ir::Function;
use crate::isa::TargetIsa;
use crate::legalize_function;
use crate::legalizer::simple_legalize;
use crate::licm::do_licm;
use crate::loop_analysis::LoopAnalysis;
use crate::machinst::MachCompileResult;
use crate::nan_canonicalization::do_nan_canonicalization;
use crate::pht_to_btb::do_pht_to_btb;
use crate::postopt::do_postopt;
use crate::redundant_reload_remover::RedundantReloadRemover;
use crate::regalloc;
use crate::result::CodegenResult;
use crate::settings::{FlagsOrIsa, OptLevel};
use crate::simple_gvn::do_simple_gvn;
use crate::simple_preopt::do_preopt;
use crate::timing;
use crate::unreachable_code::eliminate_unreachable_code;
use crate::value_label::{build_value_labels_ranges, ComparableSourceLoc, ValueLabelsRanges};
use crate::verifier::{verify_context, verify_locations, VerifierErrors, VerifierResult};
use alloc::vec::Vec;
use cranelift_spectre::settings::{
    get_spectre_mitigation, get_spectre_pht_mitigation, SpectreMitigation, SpectrePHTMitigation,
};
use log::debug;

/// Persistent data structures and compilation pipeline.
pub struct Context {
    /// The function we're compiling.
    pub func: Function,

    /// The control flow graph of `func`.
    pub cfg: ControlFlowGraph,

    /// Dominator tree for `func`.
    pub domtree: DominatorTree,

    /// Register allocation context.
    pub regalloc: regalloc::Context,

    /// Loop analysis of `func`.
    pub loop_analysis: LoopAnalysis,

    /// Redundant-reload remover context.
    pub redundant_reload_remover: RedundantReloadRemover,

    /// Result of MachBackend compilation, if computed.
    pub mach_compile_result: Option<MachCompileResult>,

    /// Flag: do we want a disassembly with the MachCompileResult?
    pub want_disasm: bool,
}

impl Context {
    /// Allocate a new compilation context.
    ///
    /// The returned instance should be reused for compiling multiple functions in order to avoid
    /// needless allocator thrashing.
    pub fn new() -> Self {
        Self::for_function(Function::new())
    }

    /// Allocate a new compilation context with an existing Function.
    ///
    /// The returned instance should be reused for compiling multiple functions in order to avoid
    /// needless allocator thrashing.
    pub fn for_function(func: Function) -> Self {
        Self {
            func,
            cfg: ControlFlowGraph::new(),
            domtree: DominatorTree::new(),
            regalloc: regalloc::Context::new(),
            loop_analysis: LoopAnalysis::new(),
            redundant_reload_remover: RedundantReloadRemover::new(),
            mach_compile_result: None,
            want_disasm: false,
        }
    }

    /// Clear all data structures in this context.
    pub fn clear(&mut self) {
        self.func.clear();
        self.cfg.clear();
        self.domtree.clear();
        self.regalloc.clear();
        self.loop_analysis.clear();
        self.redundant_reload_remover.clear();
        self.mach_compile_result = None;
        self.want_disasm = false;
    }

    /// Set the flag to request a disassembly when compiling with a
    /// `MachBackend` backend.
    pub fn set_disasm(&mut self, val: bool) {
        self.want_disasm = val;
    }

    /// Compile the function, and emit machine code into a `Vec<u8>`.
    ///
    /// Run the function through all the passes necessary to generate code for the target ISA
    /// represented by `isa`, as well as the final step of emitting machine code into a
    /// `Vec<u8>`. The machine code is not relocated. Instead, any relocations are emitted
    /// into `relocs`.
    ///
    /// This function calls `compile` and `emit_to_memory`, taking care to resize `mem` as
    /// needed, so it provides a safe interface.
    ///
    /// Returns information about the function's code and read-only data.
    pub fn compile_and_emit(
        &mut self,
        isa: &dyn TargetIsa,
        mem: &mut Vec<u8>,
        relocs: &mut dyn RelocSink,
        traps: &mut dyn TrapSink,
        stackmaps: &mut dyn StackmapSink,
    ) -> CodegenResult<CodeInfo> {
        if get_spectre_mitigation() != SpectreMitigation::NONE
            || get_spectre_pht_mitigation() != SpectrePHTMitigation::NONE
        {
            panic!("Compile and emit was called. This has not been instrumented for spectre resistance");
        }
        let info = self.compile(isa, false, &mut 0)?;
        let old_len = mem.len();
        mem.resize(old_len + info.total_size as usize, 0);
        let new_info = unsafe {
            self.emit_to_memory(isa, mem.as_mut_ptr().add(old_len), relocs, traps, stackmaps)
        };
        debug_assert!(new_info == info);
        Ok(info)
    }

    /// Compile the function.
    ///
    /// Run the function through all the passes necessary to generate code for the target ISA
    /// represented by `isa`. This does not include the final step of emitting machine code into a
    /// code sink.
    ///
    /// Returns information about the function's code and read-only data.
    pub fn compile(
        &mut self,
        isa: &dyn TargetIsa,
        can_be_indirectly_called: bool,
        cfi_start_num: &mut u64,
    ) -> CodegenResult<CodeInfo> {
        let _tt = timing::compile();
        self.verify_if(isa)?;

        let opt_level = isa.flags().opt_level();
        debug!(
            "Compiling (opt level {:?}):\n{}",
            opt_level,
            self.func.display(isa)
        );

        self.compute_cfg();
        if opt_level != OptLevel::None {
            self.preopt(isa)?;
        }
        if isa.flags().enable_nan_canonicalization() {
            self.canonicalize_nans(isa)?;
        }

        if get_spectre_pht_mitigation() == SpectrePHTMitigation::PHTTOBTB {
            self.pht_to_btb(isa)?;
        }

        self.legalize(isa)?;
        if opt_level != OptLevel::None {
            self.postopt(isa)?;
            self.compute_domtree();
            self.compute_loop_analysis();
            self.licm(isa)?;
            self.simple_gvn(isa)?;
        }

        self.compute_domtree();
        self.eliminate_unreachable_code(isa)?;
        if opt_level != OptLevel::None {
            self.dce(isa)?;
        }

        if let Some(backend) = isa.get_mach_backend() {
            let result = backend.compile_function(&self.func, self.want_disasm)?;
            let info = result.code_info();
            self.mach_compile_result = Some(result);
            Ok(info)
        } else {
            self.branch_splitting(isa)?;
            let pht_mitigation = get_spectre_pht_mitigation();
            match pht_mitigation {
                SpectrePHTMitigation::BLADE => {
                    // We do this before regalloc.
                    // It's safe because blade doesn't need to consider register unspills as dangerous
                    // loads.
                    // Register unspills can't have their address controlled by the attacker, so they
                    // can't directly produce dangerous transient data;
                    // and if transient data was stored there by a previous speculative register spill,
                    // then even the pre-regalloc blade pass will see the def-use chain across the
                    // spill-unspill and insert a fence somewhere in the chain.
                    self.blade(isa)?;
                }
                SpectrePHTMitigation::CFI => {
                    // We also do this before regalloc, because we actually need
                    // regalloc to give us some temps for the new instructions
                    // we're inserting
                    self.condbr_cfi(isa)?;
                    self.br_cfi(isa)?;
                    self.indirectbr_cfi(isa)?;

                    // add_checks also needs some temps
                    // Note that these passes very much assume that this is the final
                    // CFG and set of blocks
                    self.cfi_number_allocate(isa, cfi_start_num)?;
                    self.cfi_add_checks(isa)?;
                    self.cfi_set_correct_labels(isa)?;
                }
                _ => {}
            }
            self.regalloc(isa)?;
            self.prologue_epilogue(isa)?;
            if opt_level == OptLevel::Speed || opt_level == OptLevel::SpeedAndSize {
                self.redundant_reload_remover(isa)?;
            }
            if opt_level == OptLevel::SpeedAndSize {
                self.shrink_instructions(isa)?;
            }

            let result = self.relax_branches(isa, can_be_indirectly_called);

            debug!("Compiled:\n{}", self.func.display(isa));
            result
        }
    }

    /// Emit machine code directly into raw memory.
    ///
    /// Write all of the function's machine code to the memory at `mem`. The size of the machine
    /// code is returned by `compile` above.
    ///
    /// The machine code is not relocated. Instead, any relocations are emitted into `relocs`.
    ///
    /// # Safety
    ///
    /// This function is unsafe since it does not perform bounds checking on the memory buffer,
    /// and it can't guarantee that the `mem` pointer is valid.
    ///
    /// Returns information about the emitted code and data.
    pub unsafe fn emit_to_memory(
        &self,
        isa: &dyn TargetIsa,
        mem: *mut u8,
        relocs: &mut dyn RelocSink,
        traps: &mut dyn TrapSink,
        stackmaps: &mut dyn StackmapSink,
    ) -> CodeInfo {
        let _tt = timing::binemit();
        let mut sink = MemoryCodeSink::new(mem, relocs, traps, stackmaps);
        if let Some(ref result) = &self.mach_compile_result {
            result.sections.emit(&mut sink);
        } else {
            isa.emit_function_to_memory(&self.func, &mut sink);
        }
        sink.info
    }

    /// Creates unwind information for the function.
    ///
    /// Returns `None` if the function has no unwind information.
    #[cfg(feature = "unwind")]
    pub fn create_unwind_info(
        &self,
        isa: &dyn TargetIsa,
    ) -> CodegenResult<Option<crate::isa::unwind::UnwindInfo>> {
        isa.create_unwind_info(&self.func)
    }

    /// Run the verifier on the function.
    ///
    /// Also check that the dominator tree and control flow graph are consistent with the function.
    pub fn verify<'a, FOI: Into<FlagsOrIsa<'a>>>(&self, fisa: FOI) -> VerifierResult<()> {
        let mut errors = VerifierErrors::default();
        let _ = verify_context(&self.func, &self.cfg, &self.domtree, fisa, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Run the verifier only if the `enable_verifier` setting is true.
    pub fn verify_if<'a, FOI: Into<FlagsOrIsa<'a>>>(&self, fisa: FOI) -> CodegenResult<()> {
        let fisa = fisa.into();
        if fisa.flags.enable_verifier() {
            self.verify(fisa)?;
        }
        Ok(())
    }

    /// Run the verifier, given a function cursor and other parts of Context without
    /// needing mutable access to the Context
    pub fn full_verify(
        cur: &mut crate::cursor::EncCursor,
        cfg: &mut ControlFlowGraph,
        domtree: &mut DominatorTree,
        isa: &dyn TargetIsa,
    ) {
        cfg.compute(&cur.func);
        domtree.compute(&cur.func, &cfg);
        let mut errors = VerifierErrors::default();
        let _ = verify_context(&cur.func, &cfg, &domtree, isa, &mut errors);
        if !errors.is_empty() {
            panic!("Verifier failed!!! errors is {:?}", errors);
        }
    }

    /// Run the locations verifier on the function.
    pub fn verify_locations(&self, isa: &dyn TargetIsa) -> VerifierResult<()> {
        let mut errors = VerifierErrors::default();
        let _ = verify_locations(isa, &self.func, &self.cfg, None, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Run the locations verifier only if the `enable_verifier` setting is true.
    pub fn verify_locations_if(&self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        if isa.flags().enable_verifier() {
            self.verify_locations(isa)?;
        }
        Ok(())
    }

    /// Perform dead-code elimination on the function.
    pub fn dce<'a, FOI: Into<FlagsOrIsa<'a>>>(&mut self, fisa: FOI) -> CodegenResult<()> {
        do_dce(&mut self.func, &mut self.domtree);
        self.verify_if(fisa)?;
        Ok(())
    }

    /// Perform pre-legalization rewrites on the function.
    pub fn preopt(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_preopt(&mut self.func, &mut self.cfg, isa);
        self.verify_if(isa)?;
        Ok(())
    }

    /// Perform NaN canonicalizing rewrites on the function.
    pub fn canonicalize_nans(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_nan_canonicalization(&mut self.func);
        self.verify_if(isa)
    }

    /// Run the legalizer for `isa` on the function.
    pub fn legalize(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        // Legalization invalidates the domtree and loop_analysis by mutating the CFG.
        // TODO: Avoid doing this when legalization doesn't actually mutate the CFG.
        self.domtree.clear();
        self.loop_analysis.clear();
        if isa.get_mach_backend().is_some() {
            // Run some specific legalizations only.
            simple_legalize(&mut self.func, &mut self.cfg, isa);
            self.verify_if(isa)
        } else {
            legalize_function(&mut self.func, &mut self.cfg, isa);
            debug!("Legalized:\n{}", self.func.display(isa));
            self.verify_if(isa)
        }
    }

    /// Perform post-legalization rewrites on the function.
    pub fn postopt(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_postopt(&mut self.func, isa);
        self.verify_if(isa)?;
        Ok(())
    }

    /// Compute the control flow graph.
    pub fn compute_cfg(&mut self) {
        self.cfg.compute(&self.func)
    }

    /// Compute dominator tree.
    pub fn compute_domtree(&mut self) {
        self.domtree.compute(&self.func, &self.cfg)
    }

    /// Compute the loop analysis.
    pub fn compute_loop_analysis(&mut self) {
        self.loop_analysis
            .compute(&self.func, &self.cfg, &self.domtree)
    }

    /// Compute the control flow graph and dominator tree.
    pub fn flowgraph(&mut self) {
        self.compute_cfg();
        self.compute_domtree()
    }

    /// Perform simple GVN on the function.
    pub fn simple_gvn<'a, FOI: Into<FlagsOrIsa<'a>>>(&mut self, fisa: FOI) -> CodegenResult<()> {
        do_simple_gvn(&mut self.func, &mut self.domtree);
        self.verify_if(fisa)
    }

    /// Perform LICM on the function.
    pub fn licm(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_licm(
            isa,
            &mut self.func,
            &mut self.cfg,
            &mut self.domtree,
            &mut self.loop_analysis,
        );
        self.verify_if(isa)
    }

    /// Perform unreachable code elimination.
    pub fn eliminate_unreachable_code<'a, FOI>(&mut self, fisa: FOI) -> CodegenResult<()>
    where
        FOI: Into<FlagsOrIsa<'a>>,
    {
        eliminate_unreachable_code(&mut self.func, &mut self.cfg, &self.domtree);
        self.verify_if(fisa)
    }

    /// Split branches, add space where to add copy & regmove instructions.
    pub fn branch_splitting(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        self.regalloc.do_branch_splitting(isa, &mut self.func, &mut self.cfg, &mut self.domtree);
        self.compute_cfg();
        self.compute_domtree();
        self.verify_if(isa)
    }

    /// Run the register allocator.
    pub fn regalloc(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        self.regalloc
            .run(isa, &mut self.func, &mut self.cfg, &mut self.domtree)
    }

    /// Insert prologue and epilogues after computing the stack frame layout.
    pub fn prologue_epilogue(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        isa.prologue_epilogue(&mut self.func)?;
        self.verify_if(isa)?;
        self.verify_locations_if(isa)?;
        Ok(())
    }

    /// Do redundant-reload removal after allocation of both registers and stack slots.
    pub fn redundant_reload_remover(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        self.redundant_reload_remover
            .run(isa, &mut self.func, &self.cfg);
        self.verify_if(isa)?;
        Ok(())
    }

    /// Run the instruction shrinking pass.
    pub fn shrink_instructions(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        shrink_instructions(&mut self.func, isa);
        self.verify_if(isa)?;
        self.verify_locations_if(isa)?;
        Ok(())
    }

    /// Run the branch relaxation pass and return information about the function's code and
    /// read-only data.
    pub fn relax_branches(
        &mut self,
        isa: &dyn TargetIsa,
        can_be_indirectly_called: bool,
    ) -> CodegenResult<CodeInfo> {
        let info = relax_branches(
            &mut self.func,
            &mut self.cfg,
            &mut self.domtree,
            isa,
            can_be_indirectly_called,
        )?;
        self.verify_if(isa)?;
        self.verify_locations_if(isa)?;
        Ok(info)
    }

    /// Perform the Blade pass to insert lfences in appropriate places.
    pub fn blade(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_blade(&mut self.func, &self.cfg);
        self.verify_if(isa)
    }

    /// Perform the CFI numbering pass.
    pub fn cfi_number_allocate(&mut self, isa: &dyn TargetIsa, start_num: &mut u64) -> CodegenResult<()> {
        do_cfi_number_allocate(&mut self.func, isa, start_num);
        Ok(())
    }

    /// Actually add CFI checks
    pub fn cfi_add_checks(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_cfi_add_checks(&mut self.func, isa);
        self.verify_if(isa)
    }

    /// Replace the placeholder CFI labels with the correct ones
    pub fn cfi_set_correct_labels(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_cfi_set_correct_labels(&mut self.func, isa);
        self.verify_if(isa)
    }

    /// Insert the appropriate CFI boilerplate before each conditional branch
    pub fn condbr_cfi(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_condbr_cfi(&mut self.func, isa);
        // we recompute CFG and domtree in case they have been invalidated by the pass
        self.compute_cfg();
        self.compute_domtree();
        self.verify_if(isa)
    }

    /// Insert the appropriate CFI boilerplate before each unconditional jump
    pub fn br_cfi(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_br_cfi(&mut self.func, isa);
        // we recompute CFG and domtree in case they have been invalidated by the pass
        self.compute_cfg();
        self.compute_domtree();
        self.verify_if(isa)
    }

    /// Insert the appropriate CFI boilerplate surrounding indirect jumps (jump tables)
    pub fn indirectbr_cfi(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_indirectbr_cfi(&mut self.func, isa);
        // we recompute CFG and domtree in case they have been invalidated by the pass
        self.compute_cfg();
        self.compute_domtree();
        self.verify_if(isa)
    }

    /// Perform the pht to btb pass to replace direct branches with cmov + indirect jump.
    pub fn pht_to_btb(&mut self, isa: &dyn TargetIsa) -> CodegenResult<()> {
        do_pht_to_btb(&mut self.func, &mut self.cfg);
        self.verify_if(isa)
    }

    /// Builds ranges and location for specified value labels.
    pub fn build_value_labels_ranges(
        &self,
        isa: &dyn TargetIsa,
    ) -> CodegenResult<ValueLabelsRanges> {
        Ok(build_value_labels_ranges::<ComparableSourceLoc>(
            &self.func,
            &self.regalloc,
            isa,
        ))
    }
}
