//! Opcodes for the Pico zkVM.

use p3_field::Field;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// An opcode (short for "operation code") specifies the operation to be performed by the processor.
///
/// In the context of the RISC-V ISA, an opcode specifies which operation (i.e., addition,
/// subtraction, multiplication, etc.) to perform on up to three operands such as registers,
/// immediates, or memory addresses.
///
/// While the Pico zkVM targets the RISC-V ISA, it uses a custom instruction encoding that uses
/// a different set of opcodes. The main difference is that the Pico zkVM encodes register
/// operations and immediate operations as the same opcode. For example, the RISC-V opcodes ADD and
/// ADDI both become ADD inside the Pico zkVM. We utilize flags inside the instruction itself to
/// distinguish between the two.
///
/// Refer to the "RV32I Reference Card" [here](https://github.com/johnwinans/rvalp/releases) for
/// more details.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Opcode {
    /// rd ← rs1 + rs2, pc ← pc + 4
    ADD = 0,
    /// rd ← rs1 - rs2, pc ← pc + 4
    SUB = 1,
    /// rd ← rs1 ^ rs2, pc ← pc + 4
    XOR = 2,
    /// rd ← rs1 | rs2, pc ← pc + 4
    OR = 3,
    /// rd ← rs1 & rs2, pc ← pc + 4
    AND = 4,
    /// rd ← rs1 << rs2, pc ← pc + 4
    SLL = 5,
    /// rd ← rs1 >> rs2 (logical), pc ← pc + 4
    SRL = 6,
    /// rd ← rs1 >> rs2 (arithmetic), pc ← pc + 4
    SRA = 7,
    /// rd ← (rs1 < rs2) ? 1 : 0 (signed), pc ← pc + 4
    SLT = 8,
    /// rd ← (rs1 < rs2) ? 1 : 0 (unsigned), pc ← pc + 4
    SLTU = 9,
    /// rd ← sx(m8(rs1 + imm)), pc ← pc + 4
    LB = 10,
    /// rd ← sx(m16(rs1 + imm)), pc ← pc + 4
    LH = 11,
    /// rd ← sx(m32(rs1 + imm)), pc ← pc + 4
    LW = 12,
    /// rd ← zx(m8(rs1 + imm)), pc ← pc + 4
    LBU = 13,
    /// rd ← zx(m16(rs1 + imm)), pc ← pc + 4
    LHU = 14,
    /// m8(rs1 + imm) ← rs2[7:0], pc ← pc + 4
    SB = 15,
    /// m16(rs1 + imm) ← rs2[15:0], pc ← pc + 4
    SH = 16,
    /// m32(rs1 + imm) ← rs2[31:0], pc ← pc + 4
    SW = 17,
    /// pc ← pc + ((rs1 == rs2) ? imm : 4)
    BEQ = 18,
    /// pc ← pc + ((rs1 != rs2) ? imm : 4)
    BNE = 19,
    /// pc ← pc + ((rs1 < rs2) ? imm : 4) (signed)
    BLT = 20,
    /// pc ← pc + ((rs1 >= rs2) ? imm : 4) (signed)
    BGE = 21,
    /// pc ← pc + ((rs1 < rs2) ? imm : 4) (unsigned)
    BLTU = 22,
    /// pc ← pc + ((rs1 >= rs2) ? imm : 4) (unsigned)
    BGEU = 23,
    /// rd ← pc + 4, pc ← pc + imm
    JAL = 24,
    /// rd ← pc + 4, pc ← (rs1 + imm) & ∼1
    JALR = 25,
    /// rd ← pc + imm, pc ← pc + 4
    AUIPC = 27,
    /// Transfer control to the debugger.
    ECALL = 28,
    /// Transfer control to the operating system.
    EBREAK = 29,
    /// rd ← rs1 * rs2 (signed), pc ← pc + 4
    MUL = 30,
    /// rd ← rs1 * rs2 (half), pc ← pc + 4
    MULH = 31,
    /// rd ← rs1 * rs2 (half unsigned), pc ← pc + 4
    MULHU = 32,
    /// rd ← rs1 * rs2 (half signed unsigned), pc ← pc + 4
    MULHSU = 33,
    /// rd ← rs1 / rs2 (signed), pc ← pc + 4
    DIV = 34,
    /// rd ← rs1 / rs2 (unsigned), pc ← pc + 4
    DIVU = 35,
    /// rd ← rs1 % rs2 (signed), pc ← pc + 4
    REM = 36,
    /// rd ← rs1 % rs2 (unsigned), pc ← pc + 4
    REMU = 37,
    /// Unimplemented instruction.
    UNIMP = 39,
}

/// Byte Opcode.
///
/// This represents a basic operation that can be performed on a byte. Usually, these operations
/// are performed via lookup tables on that iterate over the domain of two 8-bit values. The
/// operations include both bitwise operations (AND, OR, XOR) as well as basic arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum ByteOpcode {
    /// Bitwise AND.
    AND = 0,
    /// Bitwise OR.
    OR = 1,
    /// Bitwise XOR.
    XOR = 2,
    /// Shift Left Logical.
    SLL = 3,
    /// Shift Right with Carry.
    ShrCarry = 4,
    /// Unsigned Less Than.
    LTU = 5,
    /// Most Significant Bit.
    MSB = 6,
    /// Unsigned 8-bit Range Check.
    U8Range = 7,
    /// Unsigned 16-bit Range Check.
    U16Range = 8,
}

/// Range Check Opcode.
///
/// This represents a type of range check that can be performed on a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum RangeCheckOpcode {
    /// Unsigned 8-bit Range Check.
    U8 = 0,
    /// Unsigned 12-bit Range Check.
    U12 = 1,
    /// Unsigned 16-bit Range Check.
    U16 = 2,
}

impl Opcode {
    /// Get the mnemonic for the opcode.
    #[must_use]
    pub const fn mnemonic(&self) -> &str {
        match self {
            Opcode::ADD => "add",
            Opcode::SUB => "sub",
            Opcode::XOR => "xor",
            Opcode::OR => "or",
            Opcode::AND => "and",
            Opcode::SLL => "sll",
            Opcode::SRL => "srl",
            Opcode::SRA => "sra",
            Opcode::SLT => "slt",
            Opcode::SLTU => "sltu",
            Opcode::LB => "lb",
            Opcode::LH => "lh",
            Opcode::LW => "lw",
            Opcode::LBU => "lbu",
            Opcode::LHU => "lhu",
            Opcode::SB => "sb",
            Opcode::SH => "sh",
            Opcode::SW => "sw",
            Opcode::BEQ => "beq",
            Opcode::BNE => "bne",
            Opcode::BLT => "blt",
            Opcode::BGE => "bge",
            Opcode::BLTU => "bltu",
            Opcode::BGEU => "bgeu",
            Opcode::JAL => "jal",
            Opcode::JALR => "jalr",
            Opcode::AUIPC => "auipc",
            Opcode::ECALL => "ecall",
            Opcode::EBREAK => "ebreak",
            Opcode::MUL => "mul",
            Opcode::MULH => "mulh",
            Opcode::MULHU => "mulhu",
            Opcode::MULHSU => "mulhsu",
            Opcode::DIV => "div",
            Opcode::DIVU => "divu",
            Opcode::REM => "rem",
            Opcode::REMU => "remu",
            Opcode::UNIMP => "unimp",
        }
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u32(self as u32)
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.mnemonic())
    }
}

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

impl From<Opcode> for ByteOpcode {
    /// Convert an opcode to a byte opcode.
    fn from(value: Opcode) -> Self {
        match value {
            Opcode::AND => Self::AND,
            Opcode::OR => Self::OR,
            Opcode::XOR => Self::XOR,
            Opcode::SLL => Self::SLL,
            _ => panic!("Invalid opcode for ByteChip: {value:?}"),
        }
    }
}

impl ByteOpcode {
    /// Get all the byte opcodes.
    #[must_use]
    pub fn all() -> Vec<Self> {
        let opcodes = vec![
            ByteOpcode::AND,
            ByteOpcode::OR,
            ByteOpcode::XOR,
            ByteOpcode::SLL,
            ByteOpcode::ShrCarry,
            ByteOpcode::LTU,
            ByteOpcode::MSB,
            ByteOpcode::U8Range,
            ByteOpcode::U16Range,
        ];
        assert_eq!(opcodes.len(), NUM_BYTE_OPS);
        opcodes
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}

impl RangeCheckOpcode {
    /// Get all the byte opcodes.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            RangeCheckOpcode::U8,
            RangeCheckOpcode::U12,
            RangeCheckOpcode::U16,
        ]
    }

    /// Convert the opcode to a field element.
    #[must_use]
    pub fn as_field<F: Field>(self) -> F {
        F::from_canonical_u8(self as u8)
    }
}
