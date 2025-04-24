use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::value_as_limbs,
        gadgets::{
            field::field_op::FieldOperation,
            is_zero::IsZeroGadget,
            uint256::U256Field,
            utils::{
                conversions::{limbs_from_access, limbs_from_prev_access},
                field_params::NumLimbs,
                limbs::Limbs,
                polynomial::Polynomial,
            },
        },
        precompiles::uint256::{
            columns::{Uint256MulCols, NUM_UINT256_MUL_COLS},
            Uint256MulChip,
        },
    },
    emulator::riscv::syscalls::SyscallCode,
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for Uint256MulChip<F> {
    fn width(&self) -> usize {
        NUM_UINT256_MUL_COLS
    }
}

impl<F: Field, CB> Air<CB> for Uint256MulChip<F>
where
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <U256Field as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Uint256MulCols<CB::Var> = (*local).borrow();

        // We are computing (x * y) % modulus. The value of x is stored in the "prev_value" of
        // the x_memory, since we write to it later.
        let x_limbs = limbs_from_prev_access(&local.x_memory);
        let y_limbs = limbs_from_access(&local.y_memory);
        let modulus_limbs = limbs_from_access(&local.modulus_memory);

        // If the modulus is zero, then we don't perform the modulus operation.
        // Evaluate the modulus_is_zero operation by summing each byte of the modulus. The sum will
        // not overflow because we are summing 32 bytes.
        let modulus_byte_sum = modulus_limbs
            .0
            .iter()
            .fold(CB::Expr::ZERO, |acc, &limb| acc + limb);
        IsZeroGadget::<CB::F>::eval(
            builder,
            modulus_byte_sum,
            local.modulus_is_zero,
            local.is_real.into(),
        );

        // If the modulus is zero, we'll actually use 2^256 as the modulus, so nothing happens.
        // Otherwise, we use the modulus passed in.
        let modulus_is_zero = local.modulus_is_zero.result;
        let mut coeff_2_256 = Vec::new();
        coeff_2_256.resize(32, CB::Expr::ZERO);
        coeff_2_256.push(CB::Expr::ONE);
        let modulus_polynomial: Polynomial<CB::Expr> = modulus_limbs.into();
        let p_modulus: Polynomial<CB::Expr> = modulus_polynomial
            * (CB::Expr::ONE - modulus_is_zero.into())
            + Polynomial::from_coefficients(&coeff_2_256) * modulus_is_zero.into();

        // Evaluate the uint256 multiplication
        local.output.eval_with_modulus(
            builder,
            &x_limbs,
            &y_limbs,
            &p_modulus,
            FieldOperation::Mul,
            local.is_real,
        );

        // Verify the range of the output if the moduls is not zero.  Also, check the value of
        // modulus_is_not_zero.
        local.output_range_check.eval(
            builder,
            &local.output.result,
            &modulus_limbs,
            local.modulus_is_not_zero,
        );
        builder.assert_eq(
            local.modulus_is_not_zero,
            local.is_real * (CB::Expr::ONE - modulus_is_zero.into()),
        );

        // Assert that the correct result is being written to x_memory.
        builder
            .when(local.is_real)
            .assert_all_eq(local.output.result, value_as_limbs(&local.x_memory));

        // Read and write x.
        for (i, access) in local.x_memory.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into() + CB::Expr::ONE,
                local.x_ptr + CB::Expr::from_canonical_usize(i * 4),
                access,
                local.is_real,
            )
        }

        // Evaluate the y_ptr memory access. We concatenate y and modulus into a single array since
        // we read it contiguously from the y_ptr memory location.
        for (i, access) in [local.y_memory, local.modulus_memory]
            .concat()
            .iter()
            .enumerate()
        {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.y_ptr + CB::Expr::from_canonical_usize(i * 4),
                access,
                local.is_real,
            )
        }

        // Receive the arguments.
        builder.looked_syscall(
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::UINT256_MUL.syscall_id()),
            local.x_ptr,
            local.y_ptr,
            local.is_real,
        );

        // Assert that is_real is a boolean.
        builder.assert_bool(local.is_real);
    }
}
