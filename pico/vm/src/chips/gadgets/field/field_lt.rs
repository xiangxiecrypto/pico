use core::fmt::Debug;
use itertools::izip;
use num::BigUint;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra, PrimeField32};
use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
        gadgets::utils::{field_params::FieldParameters, limbs::Limbs, polynomial::Polynomial},
    },
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder},
};

/// Operation columns for verifying that `lhs < rhs`.
#[derive(Clone, AlignedBorrow)]
#[repr(C)]
pub struct FieldLtCols<T, P: FieldParameters> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) byte_flags: Limbs<T, P::Limbs>,

    pub(crate) lhs_comparison_byte: T,

    pub(crate) rhs_comparison_byte: T,
}

impl<T: Debug, P: FieldParameters> Debug for FieldLtCols<T, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FieldLtCols {{ byte_flags: {:?}, lhs_comparison_byte: {:?}, rhs_comparison_byte: {:?} }}", self.byte_flags, self.lhs_comparison_byte, self.rhs_comparison_byte)
    }
}

impl<F: PrimeField32, P: FieldParameters> FieldLtCols<F, P> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, lhs: &BigUint, rhs: &BigUint) {
        assert!(lhs < rhs);

        let value_limbs = P::to_limbs(lhs);
        let modulus = P::to_limbs(rhs);

        let mut byte_flags = vec![0u8; P::NUM_LIMBS];

        for (byte, modulus_byte, flag) in izip!(
            value_limbs.iter().rev(),
            modulus.iter().rev(),
            byte_flags.iter_mut().rev()
        ) {
            assert!(byte <= modulus_byte);
            if byte < modulus_byte {
                *flag = 1;
                self.lhs_comparison_byte = F::from_canonical_u8(*byte);
                self.rhs_comparison_byte = F::from_canonical_u8(*modulus_byte);
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *byte,
                    c: *modulus_byte,
                });
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.0.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }
    }
}

impl<V: Copy, P: FieldParameters> FieldLtCols<V, P> {
    pub fn eval<
        F: Field,
        CB: ChipBuilder<F, Var = V>,
        E1: Into<Polynomial<CB::Expr>> + Clone,
        E2: Into<Polynomial<CB::Expr>> + Clone,
    >(
        &self,
        builder: &mut CB,
        lhs: &E1,
        rhs: &E2,
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
        Limbs<V, P::Limbs>: Copy,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the lhs is smaller than the modulus. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the lhs byte is equal to the modulus byte.
        // * For the `first_eq` byte the lhs byte is smaller than the modulus byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verify that only one flag is set to one.
        let mut sum_flags: CB::Expr = CB::Expr::ZERO;
        for &flag in self.byte_flags.0.iter() {
            // Assert that the flag is boolean.
            builder.when(is_real.clone()).assert_bool(flag);
            // Add the flag to the sum.
            sum_flags += flag.into();
        }
        // Assert that the sum is equal to one.
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = CB::Expr::ZERO;

        let rhs: Polynomial<_> = rhs.clone().into();
        let lhs: Polynomial<_> = lhs.clone().into();

        let mut lhs_comparison_byte = CB::Expr::ZERO;
        let mut rhs_comparison_byte = CB::Expr::ZERO;
        for (lhs_byte, rhs_byte, &flag) in izip!(
            lhs.coefficients().iter().rev(),
            rhs.coefficients().iter().rev(),
            self.byte_flags.0.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited += flag.into();

            lhs_comparison_byte += lhs_byte.clone() * flag;
            rhs_comparison_byte += flag.into() * rhs_byte.clone();

            builder
                .when(is_real.clone())
                .when_not(is_inequality_visited.clone())
                .assert_eq(lhs_byte.clone(), rhs_byte.clone());
        }

        builder
            .when(is_real.clone())
            .assert_eq(self.lhs_comparison_byte, lhs_comparison_byte);
        builder
            .when(is_real.clone())
            .assert_eq(self.rhs_comparison_byte, rhs_comparison_byte);

        // Send the comparison interaction.
        builder.looking_byte(
            ByteOpcode::LTU.as_field::<CB::F>(),
            CB::F::ONE,
            self.lhs_comparison_byte,
            self.rhs_comparison_byte,
            is_real,
        )
    }
}
