use crate::{
    chips::gadgets::field_range_check::word_range::FieldWordRangeChecker, compiler::word::Word,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BranchCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: FieldWordRangeChecker<T>,

    /// The next program counter.
    pub next_pc: Word<T>,
    pub next_pc_range_checker: FieldWordRangeChecker<T>,

    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,
}
