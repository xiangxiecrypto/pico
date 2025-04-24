use super::super::utils::make_selector_col_map;
use crate::compiler::riscv::{instruction::Instruction, opcode::Opcode};
use p3_field::Field;
use pico_derive::AlignedBorrow;
use std::{mem::size_of, vec::IntoIter};

pub const NUM_OPCODE_SELECTOR_COLS: usize = size_of::<OpcodeSelectorCols<u8>>();
pub const OPCODE_SELECTORS_COL_MAP: OpcodeSelectorCols<usize> = make_selector_col_map();

/// The column layout for opcode selectors.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct OpcodeSelectorCols<T> {
    /// Whether op_b is an immediate value.
    pub imm_b: T,

    /// Whether op_c is an immediate value.
    pub imm_c: T,

    /// Table selectors for opcodes.
    pub is_alu: T,

    /// Table selectors for opcodes.
    pub is_ecall: T,

    /// Memory Instructions.
    pub is_lb: T,
    pub is_lbu: T,
    pub is_lh: T,
    pub is_lhu: T,
    pub is_lw: T,
    pub is_sb: T,
    pub is_sh: T,
    pub is_sw: T,

    /// Branch Instructions.
    pub is_beq: T,
    pub is_bne: T,
    pub is_blt: T,
    pub is_bge: T,
    pub is_bltu: T,
    pub is_bgeu: T,

    /// Jump Instructions.
    pub is_jalr: T,
    pub is_jal: T,

    /// Miscellaneous.
    pub is_auipc: T,
    pub is_unimpl: T,
}

impl<F: Field> OpcodeSelectorCols<F> {
    pub fn populate(&mut self, instruction: Instruction) {
        self.imm_b = F::from_bool(instruction.imm_b);
        self.imm_c = F::from_bool(instruction.imm_c);

        if instruction.is_alu_instruction() {
            self.is_alu = F::ONE;
        } else if instruction.is_ecall_instruction() {
            self.is_ecall = F::ONE;
        } else if instruction.is_memory_instruction() {
            match instruction.opcode {
                Opcode::LB => self.is_lb = F::ONE,
                Opcode::LBU => self.is_lbu = F::ONE,
                Opcode::LHU => self.is_lhu = F::ONE,
                Opcode::LH => self.is_lh = F::ONE,
                Opcode::LW => self.is_lw = F::ONE,
                Opcode::SB => self.is_sb = F::ONE,
                Opcode::SH => self.is_sh = F::ONE,
                Opcode::SW => self.is_sw = F::ONE,
                _ => unreachable!(),
            }
        } else if instruction.is_branch_instruction() {
            match instruction.opcode {
                Opcode::BEQ => self.is_beq = F::ONE,
                Opcode::BNE => self.is_bne = F::ONE,
                Opcode::BLT => self.is_blt = F::ONE,
                Opcode::BGE => self.is_bge = F::ONE,
                Opcode::BLTU => self.is_bltu = F::ONE,
                Opcode::BGEU => self.is_bgeu = F::ONE,
                _ => unreachable!(),
            }
        } else if instruction.opcode == Opcode::JAL {
            self.is_jal = F::ONE;
        } else if instruction.opcode == Opcode::JALR {
            self.is_jalr = F::ONE;
        } else if instruction.opcode == Opcode::AUIPC {
            self.is_auipc = F::ONE;
        } else if instruction.opcode == Opcode::UNIMP {
            self.is_unimpl = F::ONE;
        }
    }
}

impl<T> IntoIterator for OpcodeSelectorCols<T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        let columns = vec![
            self.imm_b,
            self.imm_c,
            self.is_alu,
            self.is_ecall,
            self.is_lb,
            self.is_lbu,
            self.is_lh,
            self.is_lhu,
            self.is_lw,
            self.is_sb,
            self.is_sh,
            self.is_sw,
            self.is_beq,
            self.is_bne,
            self.is_blt,
            self.is_bge,
            self.is_bltu,
            self.is_bgeu,
            self.is_jalr,
            self.is_jal,
            self.is_auipc,
            self.is_unimpl,
        ];
        assert_eq!(columns.len(), NUM_OPCODE_SELECTOR_COLS);
        columns.into_iter()
    }
}
