//! A pass over Cranelift IR which implements the Blade algorithm

use crate::entity::{EntityRef, SecondaryMap};
use crate::flowgraph::ControlFlowGraph;
use crate::ir::{Function, Inst, InstructionData, Value, ValueDef, Opcode};
use rs_graph::linkedlistgraph::{Edge, LinkedListGraph, Node};
use rs_graph::maxflow::pushrelabel::PushRelabel;
use rs_graph::maxflow::MaxFlow;
use rs_graph::traits::Directed;
use rs_graph::Buildable;
use rs_graph::Builder;
use std::collections::HashMap;
use std::vec::Vec;

pub fn do_blade(func: &mut Function, cfg: &ControlFlowGraph) {
    let blade_graph = build_blade_graph_for_func(func, cfg);

    let cut_edges = blade_graph.min_cut();

    // insert the fences
    for cut_edge in cut_edges {
        let edge_src = blade_graph.graph.src(cut_edge);
        let edge_snk = blade_graph.graph.snk(cut_edge);
        if edge_src == blade_graph.source_node {
            // source -> n : fence after n
            insert_fence_after(
                func,
                blade_graph
                    .node_to_bladenode_map
                    .get(&edge_snk)
                    .unwrap()
                    .clone(),
            );
        } else if edge_snk == blade_graph.sink_node {
            // n -> sink : fence before (def of) n
            insert_fence_before(
                func,
                blade_graph
                    .node_to_bladenode_map
                    .get(&edge_src)
                    .unwrap()
                    .clone(),
            );
        } else {
            // n -> m : fence before m
            insert_fence_before(
                func,
                blade_graph
                    .node_to_bladenode_map
                    .get(&edge_snk)
                    .unwrap()
                    .clone(),
            );
        }
    }
}

fn insert_fence_before(func: &mut Function, bnode: BladeNode) {
    match bnode {
        BladeNode::ValueDef(val) => match func.dfg.value_def(val) {
            ValueDef::Result(inst, _) => {
                // cut at this value by putting lfence before `inst`
                func.pre_lfence[inst] = true;
            }
            ValueDef::Param(ebb, _) => {
                // cut at this value by putting lfence at beginning of
                // the `ebb`, that is, before the first instruction
                let first_inst = func
                    .layout
                    .first_inst(ebb)
                    .expect("ebb has no instructions");
                func.pre_lfence[first_inst] = true;
            }
        },
        BladeNode::Sink(inst) => {
            // cut at this instruction by putting lfence before it
            func.pre_lfence[inst] = true;
        }
    }
}

fn insert_fence_after(func: &mut Function, bnode: BladeNode) {
    match bnode {
        BladeNode::ValueDef(val) => match func.dfg.value_def(val) {
            ValueDef::Result(inst, _) => {
                // cut at this value by putting lfence after `inst`
                func.post_lfence[inst] = true;
            }
            ValueDef::Param(ebb, _) => {
                // cut at this value by putting lfence at beginning of
                // the `ebb`, that is, before the first instruction
                let first_inst = func
                    .layout
                    .first_inst(ebb)
                    .expect("ebb has no instructions");
                func.pre_lfence[first_inst] = true;
            }
        },
        BladeNode::Sink(_) => panic!("Fencing after a sink instruction"),
    }
}

/// Iterate over all of the valid load instructions in `func`
// (function is currently unused)
fn _all_load_insts<'a>(func: &'a Function) -> impl Iterator<Item = Inst> + 'a {
    // TODO: is there a better way to write this function?
    (0..func.dfg.num_insts())
        .map(Inst::new)
        .filter(move |inst| func.dfg.inst_is_valid(*inst))
        .filter(move |inst| func.dfg[*inst].opcode().can_load())
        .map(|inst| inst.clone())
}

struct DefUseGraph {
    /// Maps a value to its uses
    map: SecondaryMap<Value, Vec<ValueUse>>,
}

impl DefUseGraph {
    /// Create a `DefUseGraph` for the given `Function`.
    ///
    /// `cfg`: the `ControlFlowGraph` for the `Function`.
    pub fn for_function(func: &Function, cfg: &ControlFlowGraph) -> Self {
        let mut map: SecondaryMap<Value, Vec<ValueUse>> =
            SecondaryMap::with_capacity(func.dfg.num_values());

        for ebb in func.layout.blocks() {
            // Iterate over every instruction. Mark that instruction as a use of
            // each of its parameters.
            for inst in func.layout.block_insts(ebb) {
                for arg in func.dfg.inst_args(inst) {
                    map[*arg].push(ValueUse::Inst(inst));
                }
            }
            // Also, mark each EBB parameter as a use of the corresponding argument
            // in all branch instructions which can feed this EBB
            for incoming_bb in cfg.pred_iter(ebb) {
                // TODO: is `incoming_bb.inst` actually the appropriate
                // branch instruction which can branch here? Or is it just
                // the final instruction in the EBB? In Cranelift IR, EBBs
                // can have multiple branch instructions scattered
                // throughout.
                let incoming_branch = &func.dfg[incoming_bb.inst];
                let branch_args = match incoming_branch {
                    InstructionData::Branch { .. }
                    | InstructionData::BranchFloat { .. }
                    | InstructionData::BranchIcmp { .. }
                    | InstructionData::BranchInt { .. }
                    | InstructionData::Call { .. }
                    | InstructionData::CallIndirect { .. }
                    | InstructionData::IndirectJump { .. }
                    | InstructionData::Jump { .. } => func.dfg.inst_variable_args(incoming_bb.inst),
                    _ => panic!(
                        "incoming_branch is an unexpected type: {:?}",
                        incoming_branch
                    ),
                };
                let ebb_params = func.dfg.block_params(ebb);
                assert_eq!(branch_args.len(), ebb_params.len());
                for (param, arg) in ebb_params.iter().zip(branch_args.iter()) {
                    map[*arg].push(ValueUse::Value(*param));
                }
            }
        }

        Self { map }
    }

    /// Iterate over all the uses of the given `Value`
    pub fn uses_of_val(&self, val: Value) -> impl Iterator<Item = &ValueUse> {
        self.map[val].iter()
    }

    /// Iterate over all the uses of the result of the given `Inst` in the given `Function`
    // (function is currently unused)
    pub fn _uses_of_inst<'a>(
        &'a self,
        inst: Inst,
        func: &'a Function,
    ) -> impl Iterator<Item = &'a ValueUse> {
        func.dfg
            .inst_results(inst)
            .iter()
            .map(move |val| self.uses_of_val(*val))
            .flatten()
    }
}

/// Describes a way in which a given `Value` is used
#[derive(Clone, Debug)]
enum ValueUse {
    /// This `Instruction` uses the `Value`
    Inst(Inst),
    /// The `Value` may be forwarded to this `Value`
    Value(Value),
}

struct BladeGraph {
    /// the actual graph
    graph: LinkedListGraph<usize>,
    /// the (single) source node
    source_node: Node<usize>,
    /// the (single) sink node
    sink_node: Node<usize>,
    /// maps graph nodes to the `BladeNode`s which they correspond to
    node_to_bladenode_map: HashMap<Node<usize>, BladeNode>,
    /// maps `BladeNode`s to the graph nodes which they correspond to
    _bladenode_to_node_map: HashMap<BladeNode, Node<usize>>,
}

#[derive(PartialEq, Eq, Clone, Debug, Hash)]
enum BladeNode {
    /// A `BladeNode` representing the definition of a value
    ValueDef(Value),
    /// A `BladeNode` representing an instruction that serves as a sink
    Sink(Inst),
}

impl BladeGraph {
    /// Return the cut-edges in the mincut of the graph
    fn min_cut(&self) -> Vec<Edge<usize>> {
        // TODO: our options are `Dinic`, `EdmondsKarp`, or `PushRelabel`.
        // I'm not sure what the tradeoffs are.
        // SC: from my limited wikipedia'ing, pushrelabel is supposedly the best
        let mut maxflow = PushRelabel::<LinkedListGraph<usize>, usize>::new(&self.graph);
        maxflow.solve(self.source_node, self.sink_node, |_| 1); // all edges have weight 1

        // turns out `mincut` returns the set of nodes reachable from the source node after
        //   the graph is cut; we have to recreate the cut based on this set
        let reachable_from_source = maxflow.mincut();
        // XXX there's probably a more efficient algorithm
        reachable_from_source
            .iter()
            .map(move |node| self.graph.outedges(*node))
            .flatten()
            .filter(|(_, dst)| !reachable_from_source.contains(dst))
            .map(|(edge, _)| edge)
            .collect()
    }
}

fn build_blade_graph_for_func(func: &mut Function, cfg: &ControlFlowGraph) -> BladeGraph {
    let mut gg = LinkedListGraph::<usize>::new_builder();
    let mut node_to_bladenode_map = HashMap::new();
    let mut bladenode_to_node_map = HashMap::new();
    let source = gg.add_node(); // edges from this to sources
    let sink = gg.add_node(); // sinks have edges to this

    // first we add nodes for all possible values, and populate our maps accordingly
    for val in func.dfg.values() {
        let node = gg.add_node();
        node_to_bladenode_map.insert(node, BladeNode::ValueDef(val));
        bladenode_to_node_map.insert(BladeNode::ValueDef(val), node);
    }
    // from this point on, we can assume that `bladenode_to_node_map` is valid for all Values

    // find sources and sinks, and add edges to/from our global source and sink nodes
    for ebb in func.layout.blocks() {
        for insn in func.layout.block_insts(ebb) {
            let idata = &func.dfg[insn];
            let op = idata.opcode();
            if op.can_load() {
                // loads are both sources (their loaded values) and sinks (their addresses)
                // except for fills, which don't have sinks

                // handle load as a source
                let loaded_val = func.dfg.first_result(insn); // assume that there is only one result
                let loaded_val_node = bladenode_to_node_map[&BladeNode::ValueDef(loaded_val)];
                gg.add_edge(source, loaded_val_node);

                // handle load as a sink, except for fills
                if !(op == Opcode::Fill || op == Opcode::FillNop) {
                    let inst_sink_node = gg.add_node();
                    node_to_bladenode_map.insert(inst_sink_node, BladeNode::Sink(insn));
                    bladenode_to_node_map.insert(BladeNode::Sink(insn), inst_sink_node);
                    // for each address component variable of insn,
                    // add edge address_component_variable_node -> sink
                    // XXX X86Pop has an implicit dependency on %rsp which is not captured here
                    for arg_val in func.dfg.inst_args(insn) {
                        let arg_node = bladenode_to_node_map[&BladeNode::ValueDef(*arg_val)];
                        gg.add_edge(arg_node, inst_sink_node);
                    }
                    gg.add_edge(inst_sink_node, sink);
                }

            } else if op.can_store() {
                // loads are both sources and sinks, but stores are just sinks

                let inst_sink_node = gg.add_node();
                node_to_bladenode_map.insert(inst_sink_node, BladeNode::Sink(insn));
                bladenode_to_node_map.insert(BladeNode::Sink(insn), inst_sink_node);
                // similar to for loop above, but should skip the value being stored
                // SC: as far as I can tell, all stores (that have arguments) always
                //   have the value being stored as the first argument
                //   and everything after is address args
                // XXX X86Push has an implicit dependency on %rsp which is not captured here
                for arg_val in func.dfg.inst_args(insn).iter().skip(1) {
                    let arg_node = bladenode_to_node_map[&BladeNode::ValueDef(*arg_val)];
                    gg.add_edge(arg_node, inst_sink_node);
                }
                gg.add_edge(inst_sink_node, sink);

            } else if op.is_branch() {
                // conditional branches are sinks

                let inst_sink_node = gg.add_node();
                node_to_bladenode_map.insert(inst_sink_node, BladeNode::Sink(insn));
                bladenode_to_node_map.insert(BladeNode::Sink(insn), inst_sink_node);
                // blade only does conditional branches but this will handle indirect jumps as well
                // `inst_fixed_args` gets the condition args for branches,
                //   and ignores destination the ebb params (which are also included in args)
                for value in func.dfg.inst_fixed_args(insn) {
                    let value_node = bladenode_to_node_map[&BladeNode::ValueDef(*value)];
                    gg.add_edge(value_node, inst_sink_node);
                }
                gg.add_edge(inst_sink_node, sink);

            }
            if op.is_call() {
                // call instruction: must assume that the return value could be a source
                for result in func.dfg.inst_results(insn) {
                    let result_node = bladenode_to_node_map[&BladeNode::ValueDef(*result)];
                    gg.add_edge(source, result_node);
                }
            }
        }
    }

    // add edges to mark function parameters as potentially transient
    let entry_block = func.layout.entry_block().expect("Failed to find entry block");
    for func_param in func.dfg.block_params(entry_block) {
        // parameters of the entry block == parameters of the function
        let param_node = bladenode_to_node_map[&BladeNode::ValueDef(*func_param)];
        gg.add_edge(source, param_node);
    }

    // now add edges for actual data dependencies
    // for instance in the following pseudocode:
    //     x = load y
    //     z = x + 2
    //     branch on z
    // we have z -> sink and source -> x, but need x -> z yet
    let def_use_graph = DefUseGraph::for_function(func, cfg);
    for val in func.dfg.values() {
        let node = bladenode_to_node_map[&BladeNode::ValueDef(val)]; // must exist
        for val_use in def_use_graph.uses_of_val(val) {
            match *val_use {
                ValueUse::Inst(inst_use) => {
                    // add an edge from val to the result of inst_use
                    // TODO this assumes that all results depend on all operands;
                    // are there any instructions where this is not the case for our purposes?
                    for result in func.dfg.inst_results(inst_use) {
                        let result_node = bladenode_to_node_map[&BladeNode::ValueDef(*result)]; // must exist
                        gg.add_edge(node, result_node);
                    }
                }
                ValueUse::Value(val_use) => {
                    // add an edge from val to val_use
                    let val_use_node = bladenode_to_node_map[&BladeNode::ValueDef(val_use)]; // must exist
                    gg.add_edge(node, val_use_node);
                }
            }
        }
    }

    BladeGraph {
        graph: gg.to_graph(),
        source_node: source,
        sink_node: sink,
        node_to_bladenode_map,
        _bladenode_to_node_map: bladenode_to_node_map,
    }
}
