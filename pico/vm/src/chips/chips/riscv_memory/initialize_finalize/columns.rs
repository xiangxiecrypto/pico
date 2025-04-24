use crate::chips::gadgets::{
    field_range_check::bit_decomposition::FieldBitDecomposition, is_zero::IsZeroGadget,
    lt::AssertLtColsBits,
};
use core::mem::size_of;
use pico_derive::AlignedBorrow;

pub(crate) const NUM_MEMORY_INITIALIZE_FINALIZE_COLS: usize =
    size_of::<MemoryInitializeFinalizeCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryInitializeFinalizeCols<T> {
    /// The chunk number of the memory access.
    pub chunk: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access.
    pub addr: T,

    /// Comparison assertions for address to be strictly increasing.
    pub lt_cols: AssertLtColsBits<T, 32>,

    /// A bit decomposition of `addr`.
    pub addr_bits: FieldBitDecomposition<T>,

    /// The value of the memory access.
    pub value: [T; 32],

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the assertion `addr < addr_next`.
    pub is_next_comp: T,

    /// A witness to assert whether or not we the previous address is zero.
    pub is_prev_addr_zero: IsZeroGadget<T>,

    /// Auxilary column, equal to `(1 - is_prev_addr_zero.result) * is_first_row`.
    pub is_first_comp: T,

    /// A flag to indicate the last non-padded address. An auxiliary column needed for degree 3.
    pub is_last_addr: T,
}
