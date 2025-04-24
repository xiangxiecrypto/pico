use serde::{Deserialize, Serialize};

use crate::{
    chips::chips::riscv_memory::event::MemoryRecordEnum, compiler::riscv::instruction::Instruction,
    emulator::riscv::record::MemoryAccessRecord,
};

/// CPU Event.
///
/// This object encapsulates the information needed to prove a CPU operation. This includes its
/// chunk, opcode, operands, and other relevant information.
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct CpuEvent {
    /// The chunk number.
    pub chunk: u32,
    /// The clock cycle.
    pub clk: u32,
    /// The program counter.
    pub pc: u32,
    /// The next program counter.
    pub next_pc: u32,
    /// The instruction.
    pub instruction: Instruction,
    /// The first operand.
    pub a: u32,
    /// The first operand memory record.
    pub a_record: Option<MemoryRecordEnum>,
    /// The second operand.
    pub b: u32,
    /// The second operand memory record.
    pub b_record: Option<MemoryRecordEnum>,
    /// The third operand.
    pub c: u32,
    /// The third operand memory record.
    pub c_record: Option<MemoryRecordEnum>,
    /// The memory value.
    pub memory: Option<u32>,
    /// The memory record.
    pub memory_record: Option<MemoryRecordEnum>,
    /// The exit code.
    pub exit_code: u32,
}

impl CpuEvent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chunk: u32,
        clk: u32,
        pc: u32,
        next_pc: u32,
        instruction: Instruction,
        a: u32,
        b: u32,
        c: u32,
        memory: Option<u32>,
        record: MemoryAccessRecord,
        exit_code: u32,
    ) -> Self {
        Self {
            chunk,
            clk,
            pc,
            next_pc,
            instruction,
            a,
            a_record: record.a,
            b,
            b_record: record.b,
            c,
            c_record: record.c,
            memory,
            memory_record: record.memory,
            exit_code,
        }
    }
}
