use crate::emulator::riscv::syscalls::{
    precompiles::{PrecompileEvent, ShaExtendEvent},
    syscall_context::SyscallContext,
    Syscall, SyscallCode,
};

pub(crate) struct Sha256ExtendSyscall;

impl Syscall for Sha256ExtendSyscall {
    fn num_extra_cycles(&self) -> u32 {
        48
    }

    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: u32,
        arg2: u32,
    ) -> Option<u32> {
        let clk_init = ctx.clk;
        let w_ptr = arg1;
        assert!(arg2 == 0, "arg2 must be 0");

        let w_ptr_init = w_ptr;
        let mut w_i_minus_15_reads = Vec::new();
        let mut w_i_minus_2_reads = Vec::new();
        let mut w_i_minus_16_reads = Vec::new();
        let mut w_i_minus_7_reads = Vec::new();
        let mut w_i_writes = Vec::new();
        for i in 16..64 {
            // Read w[i-15].
            let (record, w_i_minus_15) = ctx.mr(w_ptr + (i - 15) * 4);
            w_i_minus_15_reads.push(record);

            // Compute `s0`.
            let s0 =
                w_i_minus_15.rotate_right(7) ^ w_i_minus_15.rotate_right(18) ^ (w_i_minus_15 >> 3);

            // Read w[i-2].
            let (record, w_i_minus_2) = ctx.mr(w_ptr + (i - 2) * 4);
            w_i_minus_2_reads.push(record);

            // Compute `s1`.
            let s1 =
                w_i_minus_2.rotate_right(17) ^ w_i_minus_2.rotate_right(19) ^ (w_i_minus_2 >> 10);

            // Read w[i-16].
            let (record, w_i_minus_16) = ctx.mr(w_ptr + (i - 16) * 4);
            w_i_minus_16_reads.push(record);

            // Read w[i-7].
            let (record, w_i_minus_7) = ctx.mr(w_ptr + (i - 7) * 4);
            w_i_minus_7_reads.push(record);

            // Compute `w_i`.
            let w_i = s1
                .wrapping_add(w_i_minus_16)
                .wrapping_add(s0)
                .wrapping_add(w_i_minus_7);

            // Write w[i].
            w_i_writes.push(ctx.mw(w_ptr + i * 4, w_i));
            ctx.clk += 1;
        }

        // Push the SHA extend event.
        let chunk = ctx.current_chunk();

        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            chunk,
            clk: clk_init,
            w_ptr: w_ptr_init,
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_writes,
            local_mem_access: ctx.postprocess(),
        });

        let syscall_event = ctx
            .rt
            .syscall_event(clk_init, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut()
            .add_precompile_event(syscall_code, syscall_event, event);

        None
    }
}
