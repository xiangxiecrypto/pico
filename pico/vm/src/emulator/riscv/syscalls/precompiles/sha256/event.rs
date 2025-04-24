use crate::chips::chips::riscv_memory::event::{
    MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord,
};
use serde::{Deserialize, Serialize};

/// SHA-256 Extend Event.
///
/// This event is emitted when a SHA-256 extend operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ShaExtendEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the word.
    pub w_ptr: u32,
    /// The memory reads of w[i-15].
    pub w_i_minus_15_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-2].
    pub w_i_minus_2_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-16].
    pub w_i_minus_16_reads: Vec<MemoryReadRecord>,
    /// The memory reads of w[i-7].
    pub w_i_minus_7_reads: Vec<MemoryReadRecord>,
    /// The memory writes of w[i].
    pub w_i_writes: Vec<MemoryWriteRecord>,
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// SHA-256 Compress Event.
///
/// This event is emitted when a SHA-256 compress operation is performed.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ShaCompressEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the word.
    pub w_ptr: u32,
    /// The word as a list of words.
    pub h_ptr: u32,
    /// The word as a list of words.
    pub w: Vec<u32>,
    /// The word as a list of words.
    pub h: [u32; 8],
    /// The memory records for the word.
    pub h_read_records: [MemoryReadRecord; 8],
    /// The memory records for the word.
    pub w_i_read_records: Vec<MemoryReadRecord>,
    /// The memory records for the word.
    pub h_write_records: [MemoryWriteRecord; 8],
    /// The local memory accesses.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
