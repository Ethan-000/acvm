// Re-usable methods that backends can use to implement their PWG

use std::collections::HashMap;

use crate::{Language, PartialWitnessGenerator};
use acir::{
    brillig_vm::ForeignCallResult,
    circuit::{brillig::Brillig, opcodes::BlockId, Opcode},
    native_types::{Expression, Witness, WitnessMap},
    BlackBoxFunc, FieldElement,
};

use self::{
    arithmetic::ArithmeticSolver, block::BlockSolver, brillig::BrilligSolver,
    directives::solve_directives,
};

use thiserror::Error;

// arithmetic
pub(crate) mod arithmetic;
// Brillig bytecode
mod brillig;
// Directives
mod directives;
// black box functions
mod blackbox;
mod block;

pub use brillig::ForeignCallWaitInfo;

#[derive(Debug, PartialEq)]
pub enum PartialWitnessGeneratorStatus {
    /// All opcodes have been solved.
    Solved,

    /// The ACVM has encountered a request for a Brillig [foreign call][acir::brillig_vm::Opcode::ForeignCall]
    /// to retrieve information from outside of the ACVM. The result of the foreign call must be passed back
    /// to the ACVM using [`ACVM::resolve_pending_foreign_call`].
    ///
    /// Once this is done, the ACVM can be restarted to solve the remaining opcodes.
    RequiresForeignCall,
}

#[derive(Debug, PartialEq)]
pub enum OpcodeResolution {
    /// The opcode is resolved
    Solved,
    /// The opcode is not solvable
    Stalled(OpcodeNotSolvable),
    /// The opcode is not solvable but could resolved some witness
    InProgress,
    /// The brillig oracle opcode is not solved but could be resolved given some values
    InProgressBrillig(brillig::ForeignCallWaitInfo),
}

// This enum represents the different cases in which an
// opcode can be unsolvable.
// The most common being that one of its input has not been
// assigned a value.
//
// TODO: ExpressionHasTooManyUnknowns is specific for arithmetic expressions
// TODO: we could have a error enum for arithmetic failure cases in that module
// TODO that can be converted into an OpcodeNotSolvable or OpcodeResolutionError enum
#[derive(PartialEq, Eq, Debug, Error)]
pub enum OpcodeNotSolvable {
    #[error("missing assignment for witness index {0}")]
    MissingAssignment(u32),
    #[error("expression has too many unknowns {0}")]
    ExpressionHasTooManyUnknowns(Expression),
}

#[derive(PartialEq, Eq, Debug, Error)]
pub enum OpcodeResolutionError {
    #[error("cannot solve opcode: {0}")]
    OpcodeNotSolvable(#[from] OpcodeNotSolvable),
    #[error("backend does not currently support the {0} opcode. ACVM does not currently have a fallback for this opcode.")]
    UnsupportedBlackBoxFunc(BlackBoxFunc),
    #[error("could not satisfy all constraints")]
    UnsatisfiedConstrain,
    #[error("failed to solve blackbox function: {0}, reason: {1}")]
    BlackBoxFunctionFailed(BlackBoxFunc, String),
    #[error("failed to solve brillig function, reason: {0}")]
    BrilligFunctionFailed(String),
}

pub struct ACVM<B: PartialWitnessGenerator> {
    backend: B,
    /// Stores the solver for each [block][`Opcode::Block`] opcode. This persists their internal state to prevent recomputation.
    block_solvers: HashMap<BlockId, BlockSolver>,
    /// A list of opcodes which are to be executed by the ACVM.
    ///
    /// Note that this doesn't include any opcodes which are waiting on a pending foreign call.
    opcodes: Vec<Opcode>,

    witness_map: WitnessMap,

    /// A list of foreign calls which must be resolved before the ACVM can resume execution.
    pending_foreign_calls: Vec<UnresolvedBrilligCall>,
}

impl<B: PartialWitnessGenerator> ACVM<B> {
    pub fn new(backend: B, opcodes: Vec<Opcode>, initial_witness: WitnessMap) -> Self {
        ACVM {
            backend,
            block_solvers: HashMap::default(),
            opcodes,
            witness_map: initial_witness,
            pending_foreign_calls: Vec::new(),
        }
    }

    /// Returns a reference to the current state of the ACVM's [`WitnessMap`].
    ///
    /// Once execution has completed, the witness map can be extracted using [`ACVM::finalize`]
    pub fn witness_map(&self) -> &WitnessMap {
        &self.witness_map
    }

    /// Returns a slice containing the opcodes which remain to be solved.
    ///
    /// Note: this doesn't include any opcodes which are waiting on a pending foreign call.
    pub fn unresolved_opcodes(&self) -> &[Opcode] {
        &self.opcodes
    }

    /// Finalize the ACVM execution, returning the resulting [`WitnessMap`].
    pub fn finalize(self) -> WitnessMap {
        if self.opcodes.is_empty() || self.get_pending_foreign_call().is_some() {
            panic!("ACVM is not ready to be finalized");
        }
        self.witness_map
    }

    /// Return a reference to the arguments for the next pending foreign call, if one exists.
    pub fn get_pending_foreign_call(&self) -> Option<&ForeignCallWaitInfo> {
        self.pending_foreign_calls.first().map(|foreign_call| &foreign_call.foreign_call_wait_info)
    }

    /// Resolves a pending foreign call using a result calculated outside of the ACVM.
    pub fn resolve_pending_foreign_call(&mut self, foreign_call_result: ForeignCallResult) {
        // Remove the first foreign call and inject the result to create a new opcode.
        let foreign_call = self.pending_foreign_calls.remove(0);
        let resolved_brillig = foreign_call.resolve(foreign_call_result);

        // Mark this opcode to be executed next.
        self.opcodes.insert(0, Opcode::Brillig(resolved_brillig));
    }

    /// Executes the ACVM's circuit until execution halts.
    ///
    /// Execution can halt due to three reasons:
    /// 1. All opcodes have been executed successfully.
    /// 2. The circuit has been found to be unsatisfiable.
    /// 2. A Brillig [foreign call][`UnresolvedBrilligCall`] has been encountered and must be resolved.
    pub fn solve(&mut self) -> Result<PartialWitnessGeneratorStatus, OpcodeResolutionError> {
        // TODO: Prevent execution with outstanding foreign calls?
        let mut unresolved_opcodes: Vec<Opcode> = Vec::new();
        while !self.opcodes.is_empty() {
            unresolved_opcodes.clear();
            let mut stalled = true;
            let mut opcode_not_solvable = None;
            for opcode in &self.opcodes {
                let resolution = match opcode {
                    Opcode::Arithmetic(expr) => {
                        ArithmeticSolver::solve(&mut self.witness_map, expr)
                    }
                    Opcode::BlackBoxFuncCall(bb_func) => {
                        blackbox::solve(&self.backend, &mut self.witness_map, bb_func)
                    }
                    Opcode::Directive(directive) => {
                        solve_directives(&mut self.witness_map, directive)
                    }
                    Opcode::Block(block) | Opcode::ROM(block) | Opcode::RAM(block) => {
                        let solver = self.block_solvers.entry(block.id).or_default();
                        solver.solve(&mut self.witness_map, &block.trace)
                    }
                    Opcode::Brillig(brillig) => {
                        BrilligSolver::solve(&mut self.witness_map, brillig)
                    }
                };
                match resolution {
                    Ok(OpcodeResolution::Solved) => {
                        stalled = false;
                    }
                    Ok(OpcodeResolution::InProgress) => {
                        stalled = false;
                        unresolved_opcodes.push(opcode.clone());
                    }
                    Ok(OpcodeResolution::InProgressBrillig(oracle_wait_info)) => {
                        stalled = false;
                        // InProgressBrillig Oracles must be externally re-solved
                        let brillig = match opcode {
                            Opcode::Brillig(brillig) => brillig.clone(),
                            _ => unreachable!("Brillig resolution for non brillig opcode"),
                        };
                        self.pending_foreign_calls.push(UnresolvedBrilligCall {
                            brillig,
                            foreign_call_wait_info: oracle_wait_info,
                        })
                    }
                    Ok(OpcodeResolution::Stalled(not_solvable)) => {
                        if opcode_not_solvable.is_none() {
                            // we keep track of the first unsolvable opcode
                            opcode_not_solvable = Some(not_solvable);
                        }
                        // We push those opcodes not solvable to the back as
                        // it could be because the opcodes are out of order, i.e. this assignment
                        // relies on a later opcodes' results
                        unresolved_opcodes.push(opcode.clone());
                    }
                    Err(OpcodeResolutionError::OpcodeNotSolvable(_)) => {
                        unreachable!("ICE - Result should have been converted to GateResolution")
                    }
                    Err(err) => return Err(err),
                }
            }

            // Before potentially ending execution, we must save the list of opcodes which remain to be solved.
            std::mem::swap(&mut self.opcodes, &mut unresolved_opcodes);

            // We have oracles that must be externally resolved
            if self.get_pending_foreign_call().is_some() {
                return Ok(PartialWitnessGeneratorStatus::RequiresForeignCall);
            }

            // We are stalled because of an opcode being bad
            if stalled && !self.opcodes.is_empty() {
                return Err(OpcodeResolutionError::OpcodeNotSolvable(
                    opcode_not_solvable
                        .expect("infallible: cannot be stalled and None at the same time"),
                ));
            }
        }
        Ok(PartialWitnessGeneratorStatus::Solved)
    }
}

// Returns the concrete value for a particular witness
// If the witness has no assignment, then
// an error is returned
pub fn witness_to_value(
    initial_witness: &WitnessMap,
    witness: Witness,
) -> Result<&FieldElement, OpcodeResolutionError> {
    match initial_witness.get(&witness) {
        Some(value) => Ok(value),
        None => Err(OpcodeNotSolvable::MissingAssignment(witness.0).into()),
    }
}

// TODO: There is an issue open to decide on whether we need to get values from Expressions
// TODO versus just getting values from Witness
pub fn get_value(
    expr: &Expression,
    initial_witness: &WitnessMap,
) -> Result<FieldElement, OpcodeResolutionError> {
    let expr = ArithmeticSolver::evaluate(expr, initial_witness);
    match expr.to_const() {
        Some(value) => Ok(value),
        None => {
            Err(OpcodeResolutionError::OpcodeNotSolvable(OpcodeNotSolvable::MissingAssignment(
                ArithmeticSolver::any_witness_from_expression(&expr).unwrap().0,
            )))
        }
    }
}

/// Inserts `value` into the initial witness map under the index `witness`.
///
/// Returns an error if there was already a value in the map
/// which does not match the value that one is about to insert
pub fn insert_value(
    witness: &Witness,
    value_to_insert: FieldElement,
    initial_witness: &mut WitnessMap,
) -> Result<(), OpcodeResolutionError> {
    let optional_old_value = initial_witness.insert(*witness, value_to_insert);

    let old_value = match optional_old_value {
        Some(old_value) => old_value,
        None => return Ok(()),
    };

    if old_value != value_to_insert {
        return Err(OpcodeResolutionError::UnsatisfiedConstrain);
    }

    Ok(())
}

/// A Brillig VM process has requested the caller to solve a [foreign call][brillig_vm::Opcode::ForeignCall] externally
/// and to re-run the process with the foreign call's resolved outputs.
#[derive(Debug, PartialEq, Clone)]
pub struct UnresolvedBrilligCall {
    /// The current Brillig VM process that has been paused.
    /// This process will be updated by the caller after resolving a foreign call's result.
    ///
    /// This can be done using [`UnresolvedBrilligCall::resolve`].
    pub brillig: Brillig,
    /// Inputs for a pending foreign call required to restart bytecode processing.
    pub foreign_call_wait_info: brillig::ForeignCallWaitInfo,
}

impl UnresolvedBrilligCall {
    /// Inserts the [foreign call's result][acir::brillig_vm::ForeignCallResult] into the calling [`Brillig` opcode][Brillig].
    ///
    /// The [ACVM][solve] can then be restarted with the updated [Brillig opcode][Opcode::Brillig]
    /// to solve the remaining Brillig VM process as well as the remaining ACIR opcodes.
    pub fn resolve(mut self, foreign_call_result: ForeignCallResult) -> Brillig {
        self.brillig.foreign_call_results.push(foreign_call_result);
        self.brillig
    }
}

#[deprecated(
    note = "For backwards compatibility, this method allows you to derive _sensible_ defaults for opcode support based on the np language. \n Backends should simply specify what they support."
)]
// This is set to match the previous functionality that we had
// Where we could deduce what opcodes were supported
// by knowing the np complete language
pub fn default_is_opcode_supported(language: Language) -> fn(&Opcode) -> bool {
    // R1CS does not support any of the opcode except Arithmetic by default.
    // The compiler will replace those that it can -- ie range, xor, and
    fn r1cs_is_supported(opcode: &Opcode) -> bool {
        matches!(opcode, Opcode::Arithmetic(_))
    }

    // PLONK supports most of the opcodes by default
    // The ones which are not supported, the acvm compiler will
    // attempt to transform into supported gates. If these are also not available
    // then a compiler error will be emitted.
    fn plonk_is_supported(opcode: &Opcode) -> bool {
        !matches!(opcode, Opcode::Block(_))
    }

    match language {
        Language::R1CS => r1cs_is_supported,
        Language::PLONKCSat { .. } => plonk_is_supported,
    }
}
