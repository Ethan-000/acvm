#![warn(unused_crate_dependencies)]
#![warn(unreachable_pub)]

//! The Brillig VM is a specialized VM which allows the [ACVM][acvm] to perform custom non-determinism.
//!
//! Brillig bytecode is distinct from regular [ACIR][acir] in that it does not generate constraints.
//! This is a generalization over the fixed directives that exists within in the ACVM.
//!
//! [acir]: https://crates.io/crates/acir
//! [acvm]: https://crates.io/crates/acvm

mod memory;
mod opcodes;
mod registers;
mod value;

pub use memory::Memory;
pub use opcodes::{BinaryFieldOp, BinaryIntOp, RegisterOrMemory};
pub use opcodes::{Label, Opcode};
pub use registers::{RegisterIndex, Registers};
use serde::{Deserialize, Serialize};
pub use value::Typ;
pub use value::Value;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum VMStatus {
    Finished,
    InProgress,
    Failure {
        message: String,
    },
    /// The VM process is not solvable as a [foreign call][Opcode::ForeignCall] has been
    /// reached where the outputs are yet to be resolved.  
    ///
    /// The caller should interpret the information returned to compute a [ForeignCallResult]
    /// and update the Brillig process. The VM can then be restarted to fully solve the previously
    /// unresolved foreign call as well as the remaining Brillig opcodes.
    ForeignCallWait {
        /// Interpreted by simulator context
        function: String,
        /// Input values
        /// Each input is a list of values as an input can be either a single value or a memory pointer
        inputs: Vec<Vec<Value>>,
    },
}

/// Single output of a [foreign call][Opcode::ForeignCall].
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum ForeignCallOutput {
    Single(Value),
    Array(Vec<Value>),
}

/// Represents the full output of a [foreign call][Opcode::ForeignCall].
///
/// See [`VMStatus::ForeignCallWait`] for more information.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct ForeignCallResult {
    /// Resolved output values of the foreign call.
    pub values: Vec<ForeignCallOutput>,
}

impl From<Value> for ForeignCallResult {
    fn from(value: Value) -> Self {
        ForeignCallResult { values: vec![ForeignCallOutput::Single(value)] }
    }
}

impl From<Vec<Value>> for ForeignCallResult {
    fn from(values: Vec<Value>) -> Self {
        ForeignCallResult { values: vec![ForeignCallOutput::Array(values)] }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
/// VM encapsulates the state of the Brillig VM during execution.
pub struct VM {
    /// Register storage
    registers: Registers,
    /// Instruction pointer
    program_counter: usize,
    /// A counter maintained throughout a Brillig process that determines
    /// whether the caller has resolved the results of a [foreign call][Opcode::ForeignCall].
    foreign_call_counter: usize,
    /// Represents the outputs of all foreign calls during a Brillig process
    /// List is appended onto by the caller upon reaching a [VMStatus::ForeignCallWait]
    foreign_call_results: Vec<ForeignCallResult>,
    /// Executable opcodes
    bytecode: Vec<Opcode>,
    /// Status of the VM
    status: VMStatus,
    /// Memory of the VM
    memory: Memory,
    /// Call stack
    call_stack: Vec<Value>,
}

impl VM {
    /// Constructs a new VM instance
    pub fn new(
        inputs: Registers,
        memory: Vec<Value>,
        bytecode: Vec<Opcode>,
        foreign_call_results: Vec<ForeignCallResult>,
    ) -> VM {
        Self {
            registers: inputs,
            program_counter: 0,
            foreign_call_counter: 0,
            foreign_call_results,
            bytecode,
            status: VMStatus::InProgress,
            memory: memory.into(),
            call_stack: Vec::new(),
        }
    }

    /// Updates the current status of the VM.
    /// Returns the given status.
    fn status(&mut self, status: VMStatus) -> VMStatus {
        self.status = status.clone();
        status
    }

    /// Sets the current status of the VM to Finished (completed execution).
    fn finish(&mut self) -> VMStatus {
        self.status(VMStatus::Finished)
    }

    /// Sets the status of the VM to `ForeignCallWait`.
    /// Indicating that the VM is now waiting for a foreign call to be resolved.
    fn wait_for_foreign_call(&mut self, function: String, inputs: Vec<Vec<Value>>) -> VMStatus {
        self.status(VMStatus::ForeignCallWait { function, inputs })
    }

    /// Sets the current status of the VM to `fail`.
    /// Indicating that the VM encountered a `Trap` Opcode
    /// or an invalid state.
    fn fail(&mut self, message: String) -> VMStatus {
        self.status(VMStatus::Failure { message });
        self.status.clone()
    }

    /// Loop over the bytecode and update the program counter
    pub fn process_opcodes(&mut self) -> VMStatus {
        while !matches!(
            self.process_opcode(),
            VMStatus::Finished | VMStatus::Failure { .. } | VMStatus::ForeignCallWait { .. }
        ) {}
        self.status.clone()
    }

    /// Returns all of the registers in the VM.
    pub fn get_registers(&self) -> &Registers {
        &self.registers
    }

    pub fn get_memory(&self) -> &Vec<Value> {
        self.memory.values()
    }

    /// Process a single opcode and modify the program counter.
    pub fn process_opcode(&mut self) -> VMStatus {
        let opcode = &self.bytecode[self.program_counter];
        match opcode {
            Opcode::BinaryFieldOp { op, lhs, rhs, destination: result } => {
                self.process_binary_field_op(*op, *lhs, *rhs, *result);
                self.increment_program_counter()
            }
            Opcode::BinaryIntOp { op, bit_size, lhs, rhs, destination: result } => {
                self.process_binary_int_op(*op, *bit_size, *lhs, *rhs, *result);
                self.increment_program_counter()
            }
            Opcode::Jump { location: destination } => self.set_program_counter(*destination),
            Opcode::JumpIf { condition, location: destination } => {
                // Check if condition is true
                // We use 0 to mean false and any other value to mean true
                let condition_value = self.registers.get(*condition);
                if !condition_value.is_zero() {
                    return self.set_program_counter(*destination);
                }
                self.increment_program_counter()
            }
            Opcode::JumpIfNot { condition, location: destination } => {
                let condition_value = self.registers.get(*condition);
                if condition_value.is_zero() {
                    return self.set_program_counter(*destination);
                }
                self.increment_program_counter()
            }
            Opcode::Return => {
                if let Some(register) = self.call_stack.pop() {
                    self.set_program_counter(register.to_usize())
                } else {
                    self.fail("return opcode hit, but callstack already empty".to_string())
                }
            }
            Opcode::ForeignCall { function, destinations, inputs } => {
                if self.foreign_call_counter >= self.foreign_call_results.len() {
                    // When this opcode is called, it is possible that the results of a foreign call are
                    // not yet known (not enough entries in `foreign_call_results`).
                    // If that is the case, just resolve the inputs and pause the VM with a status
                    // (VMStatus::ForeignCallWait) that communicates the foreign function name and
                    // resolved inputs back to the caller. Once the caller pushes to `foreign_call_results`,
                    // they can then make another call to the VM that starts at this opcode
                    // but has the necessary results to proceed with execution.
                    let resolved_inputs = inputs
                        .iter()
                        .map(|input| self.get_register_value_or_memory_values(*input))
                        .collect::<Vec<_>>();
                    return self.wait_for_foreign_call(function.clone(), resolved_inputs);
                }

                let ForeignCallResult { values } =
                    &self.foreign_call_results[self.foreign_call_counter];

                let mut invalid_foreign_call_result = false;
                for (destination, output) in destinations.iter().zip(values) {
                    match destination {
                        RegisterOrMemory::RegisterIndex(value_index) => match output {
                            ForeignCallOutput::Single(value) => {
                                self.registers.set(*value_index, *value)
                            }
                            _ => unreachable!(
                                "Function result size does not match brillig bytecode (expected 1 result)"
                            ),
                        },
                        RegisterOrMemory::HeapArray(pointer_index, size) => {
                            match output {
                                ForeignCallOutput::Array(values) => {
                                    if values.len() != *size {
                                        invalid_foreign_call_result = true;
                                        break;
                                    }
                                    // Convert the destination pointer to a usize
                                    let destination = self.registers.get(*pointer_index).to_usize();
                                    // Write to our destination memory
                                    self.memory.write_slice(destination, values);
                                }
                                _ => {
                                    unreachable!("Function result size does not match brillig bytecode size")
                                }
                            }
                        }
                        RegisterOrMemory::HeapVector(pointer_index, size_index) => {
                            match output {
                                ForeignCallOutput::Array(values) => {
                                    // Set our size in the size register
                                    self.registers.set(*size_index, Value::from(values.len()));
                                    // Convert the destination pointer to a usize
                                    let destination = self.registers.get(*pointer_index).to_usize();
                                    // Write to our destination memory
                                    self.memory.write_slice(destination, values);
                                }
                                _ => {
                                    unreachable!("Function result size does not match brillig bytecode size")
                                }
                            }
                        }
                    }
                }

                // These checks must come after resolving the foreign call outputs as `fail` uses a mutable reference
                if destinations.len() != values.len() {
                    self.fail(format!("{} output values were provided as a foreign call result for {} destination slots", values.len(), destinations.len()));
                }
                if invalid_foreign_call_result {
                    self.fail("Function result size does not match brillig bytecode".to_owned());
                }

                self.foreign_call_counter += 1;
                self.increment_program_counter()
            }
            Opcode::Mov { destination: destination_register, source: source_register } => {
                let source_value = self.registers.get(*source_register);
                self.registers.set(*destination_register, source_value);
                self.increment_program_counter()
            }
            Opcode::Trap => self.fail("explicit trap hit in brillig".to_string()),
            Opcode::Stop => self.finish(),
            Opcode::Load { destination: destination_register, source_pointer } => {
                // Convert our source_pointer to a usize
                let source = self.registers.get(*source_pointer);
                // Use our usize source index to lookup the value in memory
                let value = &self.memory.read(source.to_usize());
                self.registers.set(*destination_register, *value);
                self.increment_program_counter()
            }
            Opcode::Store { destination_pointer, source: source_register } => {
                // Convert our destination_pointer to a usize
                let destination = self.registers.get(*destination_pointer).to_usize();
                // Use our usize destination index to set the value in memory
                self.memory.write(destination, self.registers.get(*source_register));
                self.increment_program_counter()
            }
            Opcode::Call { location } => {
                // Push a return location
                self.call_stack.push(Value::from(self.program_counter + 1));
                self.set_program_counter(*location)
            }
            Opcode::Const { destination, value } => {
                self.registers.set(*destination, *value);
                self.increment_program_counter()
            }
        }
    }

    /// Returns the current value of the program counter.
    pub fn program_counter(self) -> usize {
        self.program_counter
    }

    /// Increments the program counter by 1.
    fn increment_program_counter(&mut self) -> VMStatus {
        self.set_program_counter(self.program_counter + 1)
    }

    /// Increments the program counter by `value`.
    /// If the program counter no longer points to an opcode
    /// in the bytecode, then the VMStatus reports halted.
    fn set_program_counter(&mut self, value: usize) -> VMStatus {
        assert!(self.program_counter < self.bytecode.len());
        self.program_counter = value;
        if self.program_counter >= self.bytecode.len() {
            self.status = VMStatus::Finished;
        }
        self.status.clone()
    }

    fn get_register_value_or_memory_values(&self, input: RegisterOrMemory) -> Vec<Value> {
        match input {
            RegisterOrMemory::RegisterIndex(value_index) => {
                vec![self.registers.get(value_index)]
            }
            RegisterOrMemory::HeapArray(pointer_index, size) => {
                let start = self.registers.get(pointer_index);
                self.memory.read_slice(start.to_usize(), size).to_vec()
            }
            RegisterOrMemory::HeapVector(pointer_index, size_index) => {
                let start = self.registers.get(pointer_index);
                let size = self.registers.get(size_index);
                self.memory.read_slice(start.to_usize(), size.to_usize()).to_vec()
            }
        }
    }

    /// Process a binary operation.
    /// This method will not modify the program counter.
    fn process_binary_field_op(
        &mut self,
        op: BinaryFieldOp,
        lhs: RegisterIndex,
        rhs: RegisterIndex,
        result: RegisterIndex,
    ) {
        let lhs_value = self.registers.get(lhs);
        let rhs_value = self.registers.get(rhs);

        let result_value = op.evaluate_field(lhs_value.to_field(), rhs_value.to_field());

        self.registers.set(result, result_value.into())
    }

    /// Process a binary operation.
    /// This method will not modify the program counter.
    fn process_binary_int_op(
        &mut self,
        op: BinaryIntOp,
        bit_size: u32,
        lhs: RegisterIndex,
        rhs: RegisterIndex,
        result: RegisterIndex,
    ) {
        let lhs_value = self.registers.get(lhs);
        let rhs_value = self.registers.get(rhs);

        let result_value = op.evaluate_int(lhs_value.to_u128(), rhs_value.to_u128(), bit_size);
        self.registers.set(result, result_value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_single_step_smoke() {
        // Load values into registers and initialize the registers that
        // will be used during bytecode processing
        let input_registers =
            Registers::load(vec![Value::from(1u128), Value::from(2u128), Value::from(0u128)]);

        // Add opcode to add the value in register `0` and `1`
        // and place the output in register `2`
        let opcode = Opcode::BinaryIntOp {
            op: BinaryIntOp::Add,
            bit_size: 2,
            lhs: RegisterIndex::from(0),
            rhs: RegisterIndex::from(1),
            destination: RegisterIndex::from(2),
        };

        // Start VM
        let mut vm = VM::new(input_registers, vec![], vec![opcode], vec![]);

        // Process a single VM opcode
        //
        // After processing a single opcode, we should have
        // the vm status as finished since there is only one opcode
        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::Finished);

        // The register at index `2` should have the value of 3 since we had an
        // add opcode
        let VM { registers, .. } = vm;
        let output_value = registers.get(RegisterIndex::from(2));

        assert_eq!(output_value, Value::from(3u128))
    }

    #[test]
    fn jmpif_opcode() {
        let mut registers = vec![];
        let mut opcodes = vec![];

        let lhs = {
            registers.push(Value::from(2u128));
            RegisterIndex::from(registers.len() - 1)
        };

        let rhs = {
            registers.push(Value::from(2u128));
            RegisterIndex::from(registers.len() - 1)
        };

        let destination = {
            registers.push(Value::from(0u128));
            RegisterIndex::from(registers.len() - 1)
        };

        let equal_cmp_opcode =
            Opcode::BinaryIntOp { op: BinaryIntOp::Equals, bit_size: 1, lhs, rhs, destination };
        opcodes.push(equal_cmp_opcode);
        opcodes.push(Opcode::Jump { location: 2 });
        opcodes.push(Opcode::JumpIf { condition: RegisterIndex::from(2), location: 3 });

        let mut vm = VM::new(Registers::load(registers), vec![], opcodes, vec![]);

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let output_cmp_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(output_cmp_value, Value::from(true));

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::Finished);
    }

    #[test]
    fn jmpifnot_opcode() {
        let input_registers =
            Registers::load(vec![Value::from(1u128), Value::from(2u128), Value::from(0u128)]);

        let trap_opcode = Opcode::Trap;

        let not_equal_cmp_opcode = Opcode::BinaryFieldOp {
            op: BinaryFieldOp::Equals,
            lhs: RegisterIndex::from(0),
            rhs: RegisterIndex::from(1),
            destination: RegisterIndex::from(2),
        };

        let jump_opcode = Opcode::Jump { location: 2 };

        let jump_if_not_opcode =
            Opcode::JumpIfNot { condition: RegisterIndex::from(2), location: 1 };

        let add_opcode = Opcode::BinaryFieldOp {
            op: BinaryFieldOp::Add,
            lhs: RegisterIndex::from(0),
            rhs: RegisterIndex::from(1),
            destination: RegisterIndex::from(2),
        };

        let mut vm = VM::new(
            input_registers,
            vec![],
            vec![jump_opcode, trap_opcode, not_equal_cmp_opcode, jump_if_not_opcode, add_opcode],
            vec![],
        );

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let output_cmp_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(output_cmp_value, Value::from(false));

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let status = vm.process_opcode();
        assert_eq!(
            status,
            VMStatus::Failure { message: "explicit trap hit in brillig".to_string() }
        );

        // The register at index `2` should have not changed as we jumped over the add opcode
        let VM { registers, .. } = vm;
        let output_value = registers.get(RegisterIndex::from(2));
        assert_eq!(output_value, Value::from(false));
    }

    #[test]
    fn mov_opcode() {
        let input_registers =
            Registers::load(vec![Value::from(1u128), Value::from(2u128), Value::from(3u128)]);

        let mov_opcode =
            Opcode::Mov { destination: RegisterIndex::from(2), source: RegisterIndex::from(0) };

        let mut vm = VM::new(input_registers, vec![], vec![mov_opcode], vec![]);

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::Finished);

        let VM { registers, .. } = vm;

        let destination_value = registers.get(RegisterIndex::from(2));
        assert_eq!(destination_value, Value::from(1u128));

        let source_value = registers.get(RegisterIndex::from(0));
        assert_eq!(source_value, Value::from(1u128));
    }

    #[test]
    fn cmp_binary_ops() {
        let bit_size = 32;
        let input_registers = Registers::load(vec![
            Value::from(2u128),
            Value::from(2u128),
            Value::from(0u128),
            Value::from(5u128),
            Value::from(6u128),
        ]);

        let equal_opcode = Opcode::BinaryIntOp {
            bit_size,
            op: BinaryIntOp::Equals,
            lhs: RegisterIndex::from(0),
            rhs: RegisterIndex::from(1),
            destination: RegisterIndex::from(2),
        };

        let not_equal_opcode = Opcode::BinaryIntOp {
            bit_size,
            op: BinaryIntOp::Equals,
            lhs: RegisterIndex::from(0),
            rhs: RegisterIndex::from(3),
            destination: RegisterIndex::from(2),
        };

        let less_than_opcode = Opcode::BinaryIntOp {
            bit_size,
            op: BinaryIntOp::LessThan,
            lhs: RegisterIndex::from(3),
            rhs: RegisterIndex::from(4),
            destination: RegisterIndex::from(2),
        };

        let less_than_equal_opcode = Opcode::BinaryIntOp {
            bit_size,
            op: BinaryIntOp::LessThanEquals,
            lhs: RegisterIndex::from(3),
            rhs: RegisterIndex::from(4),
            destination: RegisterIndex::from(2),
        };

        let mut vm = VM::new(
            input_registers,
            vec![],
            vec![equal_opcode, not_equal_opcode, less_than_opcode, less_than_equal_opcode],
            vec![],
        );

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let output_eq_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(output_eq_value, Value::from(true));

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let output_neq_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(output_neq_value, Value::from(false));

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::InProgress);

        let lt_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(lt_value, Value::from(true));

        let status = vm.process_opcode();
        assert_eq!(status, VMStatus::Finished);

        let lte_value = vm.registers.get(RegisterIndex::from(2));
        assert_eq!(lte_value, Value::from(true));
    }
    #[test]
    fn store_opcode() {
        /// Brillig code for the following:
        ///     let mut i = 0;
        ///     let len = memory.len();
        ///     while i < len {
        ///         memory[i] = i as Value;
        ///         i += 1;
        ///     }
        fn brillig_write_memory(memory: Vec<Value>) -> Vec<Value> {
            let bit_size = 32;
            let r_i = RegisterIndex::from(0);
            let r_len = RegisterIndex::from(1);
            let r_tmp = RegisterIndex::from(2);
            let start = [
                // i = 0
                Opcode::Const { destination: r_i, value: 0u128.into() },
                // len = memory.len() (approximation)
                Opcode::Const { destination: r_len, value: Value::from(memory.len() as u128) },
            ];
            let loop_body = [
                // *i = i
                Opcode::Store { destination_pointer: r_i, source: r_i },
                // tmp = 1
                Opcode::Const { destination: r_tmp, value: 1u128.into() },
                // i = i + 1 (tmp)
                Opcode::BinaryIntOp {
                    destination: r_i,
                    lhs: r_i,
                    op: BinaryIntOp::Add,
                    rhs: r_tmp,
                    bit_size,
                },
                // tmp = i < len
                Opcode::BinaryIntOp {
                    destination: r_tmp,
                    lhs: r_i,
                    op: BinaryIntOp::LessThan,
                    rhs: r_len,
                    bit_size,
                },
                // if tmp != 0 goto loop_body
                Opcode::JumpIf { condition: r_tmp, location: start.len() },
            ];
            let vm = brillig_execute_and_get_vm(memory, [&start[..], &loop_body[..]].concat());
            vm.get_memory().clone()
        }

        let memory = brillig_write_memory(vec![Value::from(0u128); 5]);
        let expected = vec![
            Value::from(0u128),
            Value::from(1u128),
            Value::from(2u128),
            Value::from(3u128),
            Value::from(4u128),
        ];
        assert_eq!(memory, expected);

        let memory = brillig_write_memory(vec![Value::from(0u128); 1024]);
        let expected: Vec<Value> = (0..1024).map(|i| Value::from(i as u128)).collect();
        assert_eq!(memory, expected);
    }

    #[test]
    fn load_opcode() {
        /// Brillig code for the following:
        ///     let mut sum = 0;
        ///     let mut i = 0;
        ///     let len = memory.len();
        ///     while i < len {
        ///         sum += memory[i];
        ///         i += 1;
        ///     }
        fn brillig_sum_memory(memory: Vec<Value>) -> Value {
            let bit_size = 32;
            let r_i = RegisterIndex::from(0);
            let r_len = RegisterIndex::from(1);
            let r_sum = RegisterIndex::from(2);
            let r_tmp = RegisterIndex::from(3);
            let start = [
                // sum = 0
                Opcode::Const { destination: r_sum, value: 0u128.into() },
                // i = 0
                Opcode::Const { destination: r_i, value: 0u128.into() },
                // len = array.len() (approximation)
                Opcode::Const { destination: r_len, value: Value::from(memory.len() as u128) },
            ];
            let loop_body = [
                // tmp = *i
                Opcode::Load { destination: r_tmp, source_pointer: r_i },
                // sum = sum + tmp
                Opcode::BinaryIntOp {
                    destination: r_sum,
                    lhs: r_sum,
                    op: BinaryIntOp::Add,
                    rhs: r_tmp,
                    bit_size,
                },
                // tmp = 1
                Opcode::Const { destination: r_tmp, value: 1u128.into() },
                // i = i + 1 (tmp)
                Opcode::BinaryIntOp {
                    destination: r_i,
                    lhs: r_i,
                    op: BinaryIntOp::Add,
                    rhs: r_tmp,
                    bit_size,
                },
                // tmp = i < len
                Opcode::BinaryIntOp {
                    destination: r_tmp,
                    lhs: r_i,
                    op: BinaryIntOp::LessThan,
                    rhs: r_len,
                    bit_size,
                },
                // if tmp != 0 goto loop_body
                Opcode::JumpIf { condition: r_tmp, location: start.len() },
            ];
            let vm = brillig_execute_and_get_vm(memory, [&start[..], &loop_body[..]].concat());
            vm.registers.get(r_sum)
        }

        assert_eq!(
            brillig_sum_memory(vec![
                Value::from(1u128),
                Value::from(2u128),
                Value::from(3u128),
                Value::from(4u128),
                Value::from(5u128),
            ]),
            Value::from(15u128)
        );
        assert_eq!(brillig_sum_memory(vec![Value::from(1u128); 1024]), Value::from(1024u128));
    }

    #[test]
    fn call_and_return_opcodes() {
        /// Brillig code for the following recursive function:
        ///     fn recursive_write(i: u128, len: u128) {
        ///         if len <= i {
        ///             return;
        ///         }
        ///         memory[i as usize] = i as Value;
        ///         recursive_write(memory, i + 1, len);
        ///     }
        /// Note we represent a 100% in-register optimized form in brillig
        fn brillig_recursive_write_memory(memory: Vec<Value>) -> Vec<Value> {
            let bit_size = 32;
            let r_i = RegisterIndex::from(0);
            let r_len = RegisterIndex::from(1);
            let r_tmp = RegisterIndex::from(2);

            let start = [
                // i = 0
                Opcode::Const { destination: r_i, value: 0u128.into() },
                // len = memory.len() (approximation)
                Opcode::Const { destination: r_len, value: Value::from(memory.len() as u128) },
                // call recursive_fn
                Opcode::Call {
                    location: 4, // Call after 'start'
                },
                // end program by jumping to end
                Opcode::Jump { location: 100 },
            ];

            let recursive_fn = [
                // tmp = len <= i
                Opcode::BinaryIntOp {
                    destination: r_tmp,
                    lhs: r_len,
                    op: BinaryIntOp::LessThanEquals,
                    rhs: r_i,
                    bit_size,
                },
                // if !tmp, goto end
                Opcode::JumpIf {
                    condition: r_tmp,
                    location: start.len() + 6, // 7 ops in recursive_fn, go to 'Return'
                },
                // *i = i
                Opcode::Store { destination_pointer: r_i, source: r_i },
                // tmp = 1
                Opcode::Const { destination: r_tmp, value: 1u128.into() },
                // i = i + 1 (tmp)
                Opcode::BinaryIntOp {
                    destination: r_i,
                    lhs: r_i,
                    op: BinaryIntOp::Add,
                    rhs: r_tmp,
                    bit_size,
                },
                // call recursive_fn
                Opcode::Call { location: start.len() },
                Opcode::Return {},
            ];

            let vm = brillig_execute_and_get_vm(memory, [&start[..], &recursive_fn[..]].concat());
            vm.get_memory().clone()
        }

        let memory = brillig_recursive_write_memory(vec![Value::from(0u128); 5]);
        let expected = vec![
            Value::from(0u128),
            Value::from(1u128),
            Value::from(2u128),
            Value::from(3u128),
            Value::from(4u128),
        ];
        assert_eq!(memory, expected);

        let memory = brillig_recursive_write_memory(vec![Value::from(0u128); 1024]);
        let expected: Vec<Value> = (0..1024).map(|i| Value::from(i as u128)).collect();
        assert_eq!(memory, expected);
    }

    fn empty_registers() -> Registers {
        Registers::load(vec![Value::from(0u128); 16])
    }
    /// Helper to execute brillig code
    fn brillig_execute_and_get_vm(memory: Vec<Value>, opcodes: Vec<Opcode>) -> VM {
        let mut vm = VM::new(empty_registers(), memory, opcodes, vec![]);
        brillig_execute(&mut vm);
        assert_eq!(vm.call_stack, vec![]);
        vm
    }

    fn brillig_execute(vm: &mut VM) {
        loop {
            let status = vm.process_opcode();
            if matches!(status, VMStatus::Finished | VMStatus::ForeignCallWait { .. }) {
                break;
            }
            assert_eq!(status, VMStatus::InProgress)
        }
    }

    #[test]
    fn foreign_call_opcode_register_result() {
        let r_input = RegisterIndex::from(0);
        let r_result = RegisterIndex::from(1);

        let double_program = vec![
            // Load input register with value 5
            Opcode::Const { destination: r_input, value: Value::from(5u128) },
            // Call foreign function "double" with the input register
            Opcode::ForeignCall {
                function: "double".into(),
                destinations: vec![RegisterOrMemory::RegisterIndex(r_result)],
                inputs: vec![RegisterOrMemory::RegisterIndex(r_input)],
            },
        ];

        let mut vm = brillig_execute_and_get_vm(vec![], double_program);

        // Check that VM is waiting
        assert_eq!(
            vm.status,
            VMStatus::ForeignCallWait {
                function: "double".into(),
                inputs: vec![vec![Value::from(5u128)]]
            }
        );

        // Push result we're waiting for
        vm.foreign_call_results.push(
            Value::from(10u128).into(), // Result of doubling 5u128
        );

        // Resume VM
        brillig_execute(&mut vm);

        // Check that VM finished once resumed
        assert_eq!(vm.status, VMStatus::Finished);

        // Check result register
        let result_value = vm.registers.get(r_result);
        assert_eq!(result_value, Value::from(10u128));

        // Ensure the foreign call counter has been incremented
        assert_eq!(vm.foreign_call_counter, 1);
    }
    #[test]
    fn foreign_call_opcode_memory_result() {
        let r_input = RegisterIndex::from(0);
        let r_output = RegisterIndex::from(1);

        // Define a simple 2x2 matrix in memory
        let initial_matrix =
            vec![Value::from(1u128), Value::from(2u128), Value::from(3u128), Value::from(4u128)];

        // Transpose of the matrix (but arbitrary for this test, the 'correct value')
        let expected_result =
            vec![Value::from(1u128), Value::from(3u128), Value::from(2u128), Value::from(4u128)];

        let invert_program = vec![
            // input = 0
            Opcode::Const { destination: r_input, value: Value::from(0u128) },
            // output = 0
            Opcode::Const { destination: r_output, value: Value::from(0u128) },
            // *output = matrix_2x2_transpose(*input)
            Opcode::ForeignCall {
                function: "matrix_2x2_transpose".into(),
                destinations: vec![RegisterOrMemory::HeapArray(r_output, initial_matrix.len())],
                inputs: vec![RegisterOrMemory::HeapArray(r_input, initial_matrix.len())],
            },
        ];

        let mut vm = brillig_execute_and_get_vm(initial_matrix.clone(), invert_program);

        // Check that VM is waiting
        assert_eq!(
            vm.status,
            VMStatus::ForeignCallWait {
                function: "matrix_2x2_transpose".into(),
                inputs: vec![initial_matrix]
            }
        );

        // Push result we're waiting for
        vm.foreign_call_results.push(expected_result.clone().into());

        // Resume VM
        brillig_execute(&mut vm);

        // Check that VM finished once resumed
        assert_eq!(vm.status, VMStatus::Finished);

        // Check result in memory
        let result_values = vm.memory.read_slice(0, 4).to_vec();
        assert_eq!(result_values, expected_result);

        // Ensure the foreign call counter has been incremented
        assert_eq!(vm.foreign_call_counter, 1);
    }

    /// Calling a simple foreign call function that takes any string input, concatenates it with itself, and reverses the concatenation
    #[test]
    fn foreign_call_opcode_vector_input_and_output() {
        let r_input_pointer = RegisterIndex::from(0);
        let r_input_size = RegisterIndex::from(1);
        // We need to pass a location of appropriate size
        let r_output_pointer = RegisterIndex::from(2);
        let r_output_size = RegisterIndex::from(3);

        // Our first string to use the identity function with
        let input_string =
            vec![Value::from(1u128), Value::from(2u128), Value::from(3u128), Value::from(4u128)];
        // Double the string (concatenate it with itself)
        let mut output_string: Vec<Value> =
            input_string.iter().cloned().chain(input_string.clone()).collect();
        // Reverse the concatenated string
        output_string.reverse();

        // First call:
        let string_double_program = vec![
            // input_pointer = 0
            Opcode::Const { destination: r_input_pointer, value: Value::from(0u128) },
            // input_size = input_string.len() (constant here)
            Opcode::Const { destination: r_input_size, value: Value::from(input_string.len()) },
            // output_pointer = 0 + input_size = input_size
            Opcode::Const { destination: r_output_pointer, value: Value::from(input_string.len()) },
            // output_size = input_size * 2
            Opcode::Const {
                destination: r_output_size,
                value: Value::from(input_string.len() * 2),
            },
            // output_pointer[0..output_size] = string_double(input_pointer[0...input_size])
            Opcode::ForeignCall {
                function: "string_double".into(),
                destinations: vec![RegisterOrMemory::HeapVector(r_output_pointer, r_output_size)],
                inputs: vec![RegisterOrMemory::HeapVector(r_input_pointer, r_input_size)],
            },
        ];

        let mut vm = brillig_execute_and_get_vm(input_string.clone(), string_double_program);

        // Check that VM is waiting
        assert_eq!(
            vm.status,
            VMStatus::ForeignCallWait {
                function: "string_double".into(),
                inputs: vec![input_string.clone()]
            }
        );

        // Push result we're waiting for
        vm.foreign_call_results.push(ForeignCallResult {
            values: vec![ForeignCallOutput::Array(output_string.clone())],
        });

        // Resume VM
        brillig_execute(&mut vm);

        // Check that VM finished once resumed
        assert_eq!(vm.status, VMStatus::Finished);

        // Check result in memory
        let result_values = vm.memory.read_slice(input_string.len(), output_string.len()).to_vec();
        assert_eq!(result_values, output_string);

        // Ensure the foreign call counter has been incremented
        assert_eq!(vm.foreign_call_counter, 1);
    }

    #[test]
    fn foreign_call_opcode_memory_alloc_result() {
        let r_input = RegisterIndex::from(0);
        let r_output = RegisterIndex::from(1);

        // Define a simple 2x2 matrix in memory
        let initial_matrix =
            vec![Value::from(1u128), Value::from(2u128), Value::from(3u128), Value::from(4u128)];

        // Transpose of the matrix (but arbitrary for this test, the 'correct value')
        let expected_result =
            vec![Value::from(1u128), Value::from(3u128), Value::from(2u128), Value::from(4u128)];

        let invert_program = vec![
            // input = 0
            Opcode::Const { destination: r_input, value: Value::from(0u128) },
            // output = 0
            Opcode::Const { destination: r_output, value: Value::from(4u128) },
            // *output = matrix_2x2_transpose(*input)
            Opcode::ForeignCall {
                function: "matrix_2x2_transpose".into(),
                destinations: vec![RegisterOrMemory::HeapArray(r_output, initial_matrix.len())],
                inputs: vec![RegisterOrMemory::HeapArray(r_input, initial_matrix.len())],
            },
        ];

        let mut vm = brillig_execute_and_get_vm(initial_matrix.clone(), invert_program);

        // Check that VM is waiting
        assert_eq!(
            vm.status,
            VMStatus::ForeignCallWait {
                function: "matrix_2x2_transpose".into(),
                inputs: vec![initial_matrix.clone()]
            }
        );

        // Push result we're waiting for
        vm.foreign_call_results.push(expected_result.clone().into());

        // Resume VM
        brillig_execute(&mut vm);

        // Check that VM finished once resumed
        assert_eq!(vm.status, VMStatus::Finished);

        // Check initial memory still in place
        let initial_values = vm.memory.read_slice(0, 4).to_vec();
        assert_eq!(initial_values, initial_matrix);

        // Check result in memory
        let result_values = vm.memory.read_slice(4, 4).to_vec();
        assert_eq!(result_values, expected_result);

        // Ensure the foreign call counter has been incremented
        assert_eq!(vm.foreign_call_counter, 1);
    }

    #[test]
    fn foreign_call_opcode_multiple_array_inputs_result() {
        let r_input_a = RegisterIndex::from(0);
        let r_input_b = RegisterIndex::from(1);
        let r_output = RegisterIndex::from(2);

        // Define a simple 2x2 matrix in memory
        let matrix_a =
            vec![Value::from(1u128), Value::from(2u128), Value::from(3u128), Value::from(4u128)];

        let matrix_b = vec![
            Value::from(10u128),
            Value::from(11u128),
            Value::from(12u128),
            Value::from(13u128),
        ];

        // Transpose of the matrix (but arbitrary for this test, the 'correct value')
        let expected_result = vec![
            Value::from(34u128),
            Value::from(37u128),
            Value::from(78u128),
            Value::from(85u128),
        ];

        let matrix_mul_program = vec![
            // input = 0
            Opcode::Const { destination: r_input_a, value: Value::from(0u128) },
            // input = 0
            Opcode::Const { destination: r_input_b, value: Value::from(4u128) },
            // output = 0
            Opcode::Const { destination: r_output, value: Value::from(0u128) },
            // *output = matrix_2x2_transpose(*input)
            Opcode::ForeignCall {
                function: "matrix_2x2_transpose".into(),
                destinations: vec![RegisterOrMemory::HeapArray(r_output, matrix_a.len())],
                inputs: vec![
                    RegisterOrMemory::HeapArray(r_input_a, matrix_a.len()),
                    RegisterOrMemory::HeapArray(r_input_b, matrix_b.len()),
                ],
            },
        ];
        let mut initial_memory = matrix_a.clone();
        initial_memory.extend(matrix_b.clone());
        let mut vm = brillig_execute_and_get_vm(initial_memory, matrix_mul_program);

        // Check that VM is waiting
        assert_eq!(
            vm.status,
            VMStatus::ForeignCallWait {
                function: "matrix_2x2_transpose".into(),
                inputs: vec![matrix_a, matrix_b]
            }
        );

        // Push result we're waiting for
        vm.foreign_call_results.push(expected_result.clone().into());

        // Resume VM
        brillig_execute(&mut vm);

        // Check that VM finished once resumed
        assert_eq!(vm.status, VMStatus::Finished);

        // Check result in memory
        let result_values = vm.memory.read_slice(0, 4).to_vec();
        assert_eq!(result_values, expected_result);

        // Ensure the foreign call counter has been incremented
        assert_eq!(vm.foreign_call_counter, 1);
    }
}
