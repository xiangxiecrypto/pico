use crate::{compiler::word::Word, primitives::consts::LOCAL_MEMORY_DATAPAR};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SingleMemoryLocal<T> {
    /// The address of the memory access.
    pub addr: T,

    /// The initial chunk of the memory access.
    pub initial_chunk: T,

    /// The final chunk of the memory access.
    pub final_chunk: T,

    /// The initial clk of the memory access.
    pub initial_clk: T,

    /// The final clk of the memory access.
    pub final_clk: T,

    /// The initial value of the memory access.
    pub initial_value: Word<T>,

    /// The final value of the memory access.
    pub final_value: Word<T>,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    pub memory_local_entries: [SingleMemoryLocal<T>; LOCAL_MEMORY_DATAPAR],
}
