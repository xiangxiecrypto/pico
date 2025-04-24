use crate::{
    compiler::word::Word,
    primitives::consts::{MAX_NUM_PVS, PV_DIGEST_NUM_WORDS},
};
use p3_field::FieldAlgebra;
use serde::{Deserialize, Serialize};
use std::borrow::{Borrow, BorrowMut};

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct PublicValues<W, T> {
    pub committed_value_digest: [W; PV_DIGEST_NUM_WORDS],

    /// The chunk's start program counter.
    pub start_pc: T,

    /// The expected start program counter for the next chunk.
    pub next_pc: T,

    /// The exit code of the program.  Only valid if halt has been executed.
    pub exit_code: T,

    /// The chunk number.
    pub chunk: T,

    /// The execution chunk number.
    pub execution_chunk: T,

    /// The bits of the largest address that is witnessed for initialization in the previous chunk.
    pub previous_initialize_addr_bits: [T; 32],

    /// The largest address that is witnessed for initialization in the current chunk.
    pub last_initialize_addr_bits: [T; 32],

    /// The bits of the largest address that is witnessed for finalization in the previous chunk.
    pub previous_finalize_addr_bits: [T; 32],

    /// The bits of the largest address that is witnessed for finalization in the current chunk.
    pub last_finalize_addr_bits: [T; 32],

    /// This field is here to ensure that the size of the public values struct is a multiple of 8.
    pub empty: [T; 3],
}

impl PublicValues<u32, u32> {
    pub fn to_vec<F: FieldAlgebra>(&self) -> Vec<F> {
        let mut pv = vec![F::ZERO; MAX_NUM_PVS];
        let field_values = PublicValues::<Word<F>, F>::from(*self);
        let pv_ref_mut: &mut PublicValues<Word<F>, F> = pv.as_mut_slice().borrow_mut();
        *pv_ref_mut = field_values;

        pv
    }
}

impl<T: Clone> Borrow<PublicValues<Word<T>, T>> for [T] {
    fn borrow(&self) -> &PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T: Clone> BorrowMut<PublicValues<Word<T>, T>> for [T] {
    fn borrow_mut(&mut self) -> &mut PublicValues<Word<T>, T> {
        let size = std::mem::size_of::<PublicValues<Word<u8>, u8>>();
        debug_assert!(self.len() >= size);
        let slice = &mut self[0..size];
        let (prefix, shorts, _suffix) = unsafe { slice.align_to_mut::<PublicValues<Word<T>, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<F: FieldAlgebra> From<PublicValues<u32, u32>> for PublicValues<Word<F>, F> {
    fn from(value: PublicValues<u32, u32>) -> Self {
        let PublicValues {
            committed_value_digest,
            start_pc,
            next_pc,
            exit_code,
            chunk,
            execution_chunk,
            previous_initialize_addr_bits,
            last_initialize_addr_bits,
            previous_finalize_addr_bits,
            last_finalize_addr_bits,
            ..
        } = value;

        let committed_value_digest: [_; PV_DIGEST_NUM_WORDS] =
            core::array::from_fn(|i| Word::from(committed_value_digest[i]));

        let start_pc = F::from_canonical_u32(start_pc);
        let next_pc = F::from_canonical_u32(next_pc);
        let exit_code = F::from_canonical_u32(exit_code);
        let chunk = F::from_canonical_u32(chunk);
        let execution_chunk = F::from_canonical_u32(execution_chunk);
        let previous_initialize_addr_bits =
            previous_initialize_addr_bits.map(F::from_canonical_u32);
        let last_initialize_addr_bits = last_initialize_addr_bits.map(F::from_canonical_u32);
        let previous_finalize_addr_bits = previous_finalize_addr_bits.map(F::from_canonical_u32);
        let last_finalize_addr_bits = last_finalize_addr_bits.map(F::from_canonical_u32);

        Self {
            committed_value_digest,
            start_pc,
            next_pc,
            exit_code,
            chunk,
            execution_chunk,
            previous_initialize_addr_bits,
            last_initialize_addr_bits,
            previous_finalize_addr_bits,
            last_finalize_addr_bits,
            empty: [F::ZERO, F::ZERO, F::ZERO],
        }
    }
}
