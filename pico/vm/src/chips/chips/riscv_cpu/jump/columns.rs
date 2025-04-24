use crate::{
    chips::gadgets::field_range_check::word_range::FieldWordRangeChecker, compiler::word::Word,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_JUMP_COLS: usize = size_of::<JumpCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct JumpCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: FieldWordRangeChecker<T>,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: FieldWordRangeChecker<T>,

    // A range checker for `op_a` which may contain `pc + 4`.
    pub op_a_range_checker: FieldWordRangeChecker<T>,
}
