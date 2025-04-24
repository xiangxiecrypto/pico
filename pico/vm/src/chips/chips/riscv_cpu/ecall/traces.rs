use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{riscv_cpu::event::CpuEvent, riscv_memory::read_write::columns::MemoryCols},
    emulator::riscv::syscalls::SyscallCode,
};
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to ECALL.
    pub(crate) fn populate_ecall(&self, cols: &mut CpuCols<F>, event: &CpuEvent) -> bool {
        let mut is_halt = false;

        if cols.opcode_selector.is_ecall == F::ONE {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and
            // explanation.
            let ecall_cols = cols.opcode_specific.ecall_mut();

            cols.ecall_mul_send_to_table =
                cols.opcode_selector.is_ecall * cols.op_a_access.prev_value[1];

            let syscall_id = cols.op_a_access.prev_value[0];
            // let send_to_table = cols.op_a_access.prev_value[1];
            // let num_cycles = cols.op_a_access.prev_value[2];

            // Populate `is_enter_unconstrained`.
            ecall_cols
                .is_enter_unconstrained
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                );

            // Populate `is_hint_len`.
            ecall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
            );

            // Populate `is_halt`.
            ecall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            ecall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
            // digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()) {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::ONE;
            }

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

            // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
            // it's operands.
            if is_halt {
                ecall_cols.operand_to_check = event.b.into();
                ecall_cols.operand_range_check_cols.populate(event.b);
                cols.ecall_range_check_operand = F::ONE;
            }
        }

        is_halt
    }
}
