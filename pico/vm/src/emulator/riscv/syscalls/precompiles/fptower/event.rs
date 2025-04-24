use crate::chips::{
    chips::riscv_memory::event::{MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord},
    gadgets::field::field_op::FieldOperation,
};
use serde::{Deserialize, Serialize};

/// Base field events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct FpEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Box<[u32]>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Box<[u32]>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Fp2 addition and subtraction events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2AddSubEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Box<[u32]>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Box<[u32]>,
    /// The operation to perform.
    pub op: FieldOperation,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}

/// Fp2 multiplication events
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct Fp2MulEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The pointer to the x operand.
    pub x_ptr: u32,
    /// The x operand.
    pub x: Box<[u32]>,
    /// The pointer to the y operand.
    pub y_ptr: u32,
    /// The y operand.
    pub y: Box<[u32]>,
    /// The memory records for the x operand.
    pub x_memory_records: Box<[MemoryWriteRecord]>,
    /// The memory records for the y operand.
    pub y_memory_records: Box<[MemoryReadRecord]>,
    /// The local memory access records.
    pub local_mem_access: Vec<MemoryLocalEvent>,
}
