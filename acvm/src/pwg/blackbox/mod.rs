use acir::{
    circuit::opcodes::{BlackBoxFuncCall, FunctionInput},
    native_types::{Witness, WitnessMap},
};

use super::{OpcodeNotSolvable, OpcodeResolution, OpcodeResolutionError};
use crate::PartialWitnessGenerator;

mod ecdsa;
mod hash;
mod logic;
mod range;

use ecdsa::secp256k1_prehashed;
// Hash functions should eventually be exposed for external consumers.
use hash::{blake2s256, keccak256, sha256};
use hash::{hash_to_field_128_security, solve_generic_256_hash_opcode};
use logic::{and, xor};
use range::solve_range_opcode;

/// Check if all of the inputs to the function have assignments
///
/// Returns the first missing assignment if any are missing
fn first_missing_assignment(
    witness_assignments: &WitnessMap,
    inputs: &[FunctionInput],
) -> Option<Witness> {
    inputs.iter().find_map(|input| {
        if witness_assignments.contains_key(&input.witness) {
            None
        } else {
            Some(input.witness)
        }
    })
}

/// Check if all of the inputs to the function have assignments
fn contains_all_inputs(witness_assignments: &WitnessMap, inputs: &[FunctionInput]) -> bool {
    inputs.iter().all(|input| witness_assignments.contains_key(&input.witness))
}

pub(crate) fn solve(
    backend: &impl PartialWitnessGenerator,
    initial_witness: &mut WitnessMap,
    bb_func: &BlackBoxFuncCall,
) -> Result<OpcodeResolution, OpcodeResolutionError> {
    let inputs = bb_func.get_inputs_vec();
    if !contains_all_inputs(initial_witness, &inputs) {
        let unassigned_witness = first_missing_assignment(initial_witness, &inputs)
            .expect("Some assignments must be missing because it does not contains all inputs");
        return Ok(OpcodeResolution::Stalled(OpcodeNotSolvable::MissingAssignment(
            unassigned_witness.0,
        )));
    }

    match bb_func {
        BlackBoxFuncCall::AND { lhs, rhs, output } => and(initial_witness, lhs, rhs, output),
        BlackBoxFuncCall::XOR { lhs, rhs, output } => xor(initial_witness, lhs, rhs, output),
        BlackBoxFuncCall::RANGE { input } => solve_range_opcode(initial_witness, input),
        BlackBoxFuncCall::SHA256 { inputs, outputs } => solve_generic_256_hash_opcode(
            initial_witness,
            inputs,
            None,
            outputs,
            sha256,
            bb_func.get_black_box_func(),
        ),
        BlackBoxFuncCall::Blake2s { inputs, outputs } => solve_generic_256_hash_opcode(
            initial_witness,
            inputs,
            None,
            outputs,
            blake2s256,
            bb_func.get_black_box_func(),
        ),
        BlackBoxFuncCall::Keccak256 { inputs, outputs } => solve_generic_256_hash_opcode(
            initial_witness,
            inputs,
            None,
            outputs,
            keccak256,
            bb_func.get_black_box_func(),
        ),
        BlackBoxFuncCall::Keccak256VariableLength { inputs, var_message_size, outputs } => {
            solve_generic_256_hash_opcode(
                initial_witness,
                inputs,
                Some(var_message_size),
                outputs,
                keccak256,
                bb_func.get_black_box_func(),
            )
        }
        BlackBoxFuncCall::HashToField128Security { inputs, output } => {
            hash_to_field_128_security(initial_witness, inputs, output)
        }
        BlackBoxFuncCall::SchnorrVerify {
            public_key_x,
            public_key_y,
            signature_s,
            signature_e,
            message,
            output,
        } => backend.schnorr_verify(
            initial_witness,
            *public_key_x,
            *public_key_y,
            *signature_s,
            *signature_e,
            message,
            *output,
        ),
        BlackBoxFuncCall::Pedersen { inputs, domain_separator, outputs } => {
            backend.pedersen(initial_witness, inputs, *domain_separator, *outputs)
        }
        BlackBoxFuncCall::EcdsaSecp256k1 {
            public_key_x,
            public_key_y,
            signature,
            hashed_message: message,
            output,
        } => secp256k1_prehashed(
            initial_witness,
            public_key_x,
            public_key_y,
            signature,
            message,
            *output,
        ),
        BlackBoxFuncCall::FixedBaseScalarMul { input, outputs } => {
            backend.fixed_base_scalar_mul(initial_witness, *input, *outputs)
        }
        BlackBoxFuncCall::RecursiveAggregation { .. } => Ok(OpcodeResolution::Solved),
    }
}
