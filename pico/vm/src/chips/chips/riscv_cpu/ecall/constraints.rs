use super::super::{columns::CpuCols, opcode_selector::columns::OpcodeSelectorCols, CpuChip};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{field_range_check::word_range::FieldWordRangeChecker, is_zero::IsZeroGadget},
    },
    compiler::word::Word,
    emulator::riscv::{public_values::PublicValues, syscalls::SyscallCode},
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, ChipWordBuilder},
    primitives::consts::PV_DIGEST_NUM_WORDS,
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

impl<F: Field> CpuChip<F> {
    /// Whether the instruction is an ECALL instruction.
    pub(crate) fn is_ecall_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_ecall.into()
    }

    /// Constraints related to the ECALL opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_ecall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        let ecall_cols = local.opcode_specific.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // We interpret the syscall_code as little-endian bytes and interpret each byte as a u8
        // with different information.
        let syscall_id = syscall_code[0];
        let send_to_table = syscall_code[1];

        // Handle cases:
        // - is_ecall_instruction = 1 => ecall_mul_send_to_table == send_to_table
        // - is_ecall_instruction = 0 => ecall_mul_send_to_table == 0
        builder.assert_eq(
            local.ecall_mul_send_to_table,
            send_to_table * is_ecall_instruction.clone(),
        );

        builder.looking_syscall(
            local.clk,
            syscall_id,
            local.op_b_val().reduce::<CB>(),
            local.op_c_val().reduce::<CB>(),
            local.ecall_mul_send_to_table,
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id
                    - CB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                ecall_cols.is_enter_unconstrained,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                ecall_cols.is_hint_len,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_hint_len.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word::<CB::F>::from(0);
        builder
            .when(is_ecall_instruction.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_val(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(is_ecall_instruction.clone())
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // Verify value of ecall_range_check_operand column.
        builder.assert_eq(
            local.ecall_range_check_operand,
            is_ecall_instruction * ecall_cols.is_halt.result,
        );

        // Range check the operand_to_check word.
        FieldWordRangeChecker::<CB::F>::range_check::<CB>(
            builder,
            ecall_cols.operand_to_check,
            ecall_cols.operand_range_check_cols,
            local.ecall_range_check_operand.into(),
        );
    }

    /// Constraints related to the COMMIT instruction.
    pub(crate) fn eval_commit<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        commit_digest: [Word<CB::Expr>; PV_DIGEST_NUM_WORDS],
    ) {
        let is_commit = self.get_is_commit_related_syscall(builder, local);

        // Get the ecall specific columns.
        let ecall_columns = local.opcode_specific.ecall();

        // Verify the index bitmap.
        let mut bitmap_sum = CB::Expr::ZERO;
        // They should all be bools.
        for bit in ecall_columns.index_bitmap.iter() {
            builder
                .when(local.opcode_selector.is_ecall)
                .assert_bool(*bit);
            bitmap_sum += (*bit).into();
        }
        // When the syscall is COMMIT, there should be one set bit.
        builder
            .when(local.opcode_selector.is_ecall * is_commit.clone())
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(local.opcode_selector.is_ecall * (CB::Expr::ONE - is_commit.clone()))
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in ecall_columns.index_bitmap.iter().enumerate() {
            builder
                .when(*bit * local.opcode_selector.is_ecall)
                .assert_eq(
                    local.op_b_access.prev_value()[0],
                    CB::Expr::from_canonical_u32(i as u32),
                );
        }

        // Verify that the 3 upper bytes of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(local.opcode_selector.is_ecall * is_commit.clone())
                .assert_eq(
                    local.op_b_access.prev_value()[i + 1],
                    CB::Expr::from_canonical_u32(0),
                );
        }

        // Retrieve the expected public values digest word to check against the one passed into the
        // commit ecall. Note that for the interaction builder, it will not have any digest words,
        // since it's used during AIR compilation time to parse for all send/receives. Since
        // that interaction builder will ignore the other constraints of the air, it is safe
        // to not include the verification check of the expected public values digest word.
        let expected_pv_digest_word =
            builder.index_word_array(&commit_digest, &ecall_columns.index_bitmap);

        let digest_word = local.op_c_access.prev_value();

        // Verify the public_values_digest_word.
        builder
            .when(local.opcode_selector.is_ecall * is_commit)
            .assert_word_eq(expected_pv_digest_word, *digest_word);
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
        public_values: &PublicValues<Word<CB::Expr>, CB::Expr>,
    ) {
        let is_halt = self.get_is_halt_syscall(builder, local);

        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(is_halt.clone() + local.opcode_selector.is_unimpl)
            .assert_zero(next.is_real);

        builder.when(is_halt.clone()).assert_zero(local.next_pc);

        // Verify that the operand that was range checked is op_b.
        let ecall_columns = local.opcode_specific.ecall();
        builder
            .when(is_halt.clone())
            .assert_word_eq(local.op_b_val(), ecall_columns.operand_to_check);

        builder.when(is_halt.clone()).assert_eq(
            local.op_b_access.value().reduce::<CB>(),
            public_values.exit_code.clone(),
        );
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn get_is_halt_syscall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let ecall_cols = local.opcode_specific.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is HALT.
        let is_halt = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                ecall_cols.is_halt,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_halt.result
        };

        is_halt * is_ecall_instruction
    }

    /// Returns boolean expression indicating whether the instruction is a COMMIT instruction.
    pub(crate) fn get_is_commit_related_syscall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let ecall_cols = local.opcode_specific.ecall();

        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let syscall_id = syscall_code[0];

        // Compute whether this ecall is COMMIT.
        let is_commit = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                ecall_cols.is_commit,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit.result
        };

        is_commit.into()
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    pub(crate) fn get_num_extra_ecall_cycles<CB: ChipBuilder<F>>(
        &self,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let num_extra_cycles = syscall_code[2];

        num_extra_cycles * is_ecall_instruction.clone()
    }
}
