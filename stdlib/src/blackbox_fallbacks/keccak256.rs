use super::{
    sha256::pad,
    uint8::UInt8,
    utils::{byte_decomposition, round_to_nearest_byte},
};
use acir::{
    circuit::Opcode,
    native_types::{Expression, Witness},
    FieldElement,
};

const BITS: usize = 256;
const WORD_SIZE: usize = 8;
const BLOCK_SIZE: usize = (1600 - BITS * 2) / WORD_SIZE;

pub fn keccak256(
    inputs: Vec<(Expression, u32)>,
    outputs: Vec<Witness>,
    mut num_witness: u32,
) -> (u32, Vec<Opcode>) {
    let mut new_gates = Vec::new();
    let mut new_inputs = Vec::new();

    // Decompose the input field elements into bytes and collect the resulting witnesses.
    for (witness, num_bits) in inputs {
        let num_bytes = round_to_nearest_byte(num_bits);
        let (extra_gates, inputs, updated_witness_counter) =
            byte_decomposition(witness, num_bytes, num_witness);
        new_gates.extend(extra_gates);
        new_inputs.extend(inputs);
        num_witness = updated_witness_counter;
    }

    let (result, num_witness, extra_gates) = create_keccak_constraint(new_inputs, num_witness);
    new_gates.extend(extra_gates);

    // constrain the outputs to be the same as the result of the circuit
    for i in 0..outputs.len() {
        let mut expr = Expression::from(outputs[i]);
        expr.push_addition_term(-FieldElement::one(), result[i]);
        new_gates.push(Opcode::Arithmetic(expr));
    }
    (num_witness, new_gates)
}

fn create_keccak_constraint(
    input: Vec<Witness>,
    num_witness: u32,
) -> (Vec<Witness>, u32, Vec<Opcode>) {
    let mut new_gates = Vec::new();
    let num_blocks = input.len() / BLOCK_SIZE + 1;

    let (input, extra_gates, num_witness) = pad_keccak(input, num_blocks, num_witness);
    new_gates.extend(extra_gates);

    (vec![], num_witness, new_gates)
}

fn pad_keccak(
    mut input: Vec<Witness>,
    num_blocks: usize,
    num_witness: u32,
) -> (Vec<Witness>, Vec<Opcode>, u32) {
    let mut new_gates = Vec::new();
    let total_len = BLOCK_SIZE * num_blocks;

    let (mut num_witness, pad_witness, extra_gates) = pad(0x01, 8, num_witness);
    new_gates.extend(extra_gates);
    input.push(pad_witness);

    for _ in 0..total_len {
        let (updated_witness_counter, pad_witness, extra_gates) = pad(0x00, 8, num_witness);
        new_gates.extend(extra_gates);
        input.push(pad_witness);
        num_witness = updated_witness_counter;
    }

    let (zero_x_80, extra_gates, num_witness) = UInt8::load_constant(0x80, num_witness);
    new_gates.extend(extra_gates);

    let (final_pad, extra_gates, num_witness) =
        UInt8::new(input[total_len - 1]).xor(&zero_x_80, num_witness);

    input[total_len - 1] = final_pad.inner;

    (input, extra_gates, num_witness)
}
