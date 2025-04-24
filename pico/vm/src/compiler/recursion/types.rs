// TODO: move parts of the code to compiler

use p3_field::PrimeField64;
use pico_derive::AlignedBorrow;
use serde::{Deserialize, Serialize};

use crate::{
    compiler::recursion::ir::Block,
    emulator::recursion::{emulator::*, public_values::RecursionPublicValues},
};

pub const WIDTH: usize = 16;

#[derive(
    AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F: PrimeField64> Address<F> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0.as_canonical_u64() as usize
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type BaseAluEvent<F> = BaseAluIo<F>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaseAluInstr<F> {
    pub opcode: BaseAluOpcode,
    pub mult: F,
    pub addrs: BaseAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the extension field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

pub type ExtAluEvent<F> = ExtAluIo<Block<F>>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtAluInstr<F> {
    pub opcode: ExtAluOpcode,
    pub mult: F,
    pub addrs: ExtAluIo<Address<F>>,
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to the manual memory management/memory initialization table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemIo<V> {
    pub inner: V,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
    pub kind: MemAccessKind,
}

// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    Read,
    Write,
}

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poseidon2Io<V> {
    pub input: [V; WIDTH],
    pub output: [V; WIDTH],
}

/// An instruction invoking the Poseidon2 permutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Poseidon2SkinnyInstr<F> {
    pub addrs: Poseidon2Io<Address<F>>,
    pub mults: [F; WIDTH],
}

pub type Poseidon2Event<F> = Poseidon2Io<F>;

/*
Select-related
 */

/// The inputs and outputs to a select operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectIo<V> {
    pub bit: V,
    pub out1: V,
    pub out2: V,
    pub in1: V,
    pub in2: V,
}

/// An instruction invoking the select operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectInstr<F> {
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

/// The event encoding the inputs and outputs of a select operation.
pub type SelectEvent<F> = SelectIo<F>;

/*
ExpReverseBits-related
 */

/// The inputs and outputs to an exp-reverse-bits operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsIo<V> {
    pub base: V,
    // The bits of the exponent in little-endian order in a vec.
    pub exp: Vec<V>,
    pub result: V,
}

pub type Poseidon2Instr<F> = Poseidon2SkinnyInstr<F>;

/// An instruction invoking the exp-reverse-bits operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpReverseBitsInstr<F> {
    pub addrs: ExpReverseBitsIo<Address<F>>,
    pub mult: F,
}

/// The event encoding the inputs and outputs of an exp-reverse-bits operation. The `len` operand is
/// now stored as the length of the `exp` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsEvent<F> {
    pub base: F,
    pub exp: Vec<F>,
    pub result: F,
}

/*
BatchFRI-related
 */

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIIo<V> {
    pub ext_single: BatchFRIExtSingleIo<Block<V>>,
    pub ext_vec: BatchFRIExtVecIo<Vec<Block<V>>>,
    pub base_vec: BatchFRIBaseVecIo<V>,
}

/// The extension-field-valued single inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtSingleIo<V> {
    pub acc: V,
}

/// The extension-field-valued vector inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtVecIo<V> {
    pub p_at_z: V,
    pub alpha_pow: V,
}

/// The base-field-valued vector inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIBaseVecIo<V> {
    pub p_at_x: V,
}

/// An instruction invoking the batch FRI operation. Addresses for extension field elements are of
/// the same type as for base field elements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIInstr<F> {
    pub base_vec_addrs: BatchFRIBaseVecIo<Vec<Address<F>>>,
    pub ext_single_addrs: BatchFRIExtSingleIo<Address<F>>,
    pub ext_vec_addrs: BatchFRIExtVecIo<Vec<Address<F>>>,
    pub acc_mult: F,
}

/// The event encoding the data of a single iteration within the batch FRI operation.
/// For any given event, we are accessing a single element of the `Vec` inputs, so that the event
/// is not a type alias for `BatchFRIIo` like many of the other events.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIEvent<F> {
    pub base_vec: BatchFRIBaseVecIo<F>,
    pub ext_single: BatchFRIExtSingleIo<Block<F>>,
    pub ext_vec: BatchFRIExtVecIo<Block<F>>,
}

/*
Public values-related
 */
/// An instruction that will save the public values to the execution record and will commit to
/// it's digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitPublicValuesInstr<F> {
    pub pv_addrs: RecursionPublicValues<Address<F>>,
}

/// The event for committing to the public values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitPublicValuesEvent<F> {
    pub public_values: RecursionPublicValues<F>,
}
