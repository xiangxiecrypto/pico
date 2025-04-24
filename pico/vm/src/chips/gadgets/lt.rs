//! Bytes less than gadget

use crate::{
    chips::chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder},
};
use itertools::izip;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// Gadget columns for verifying that a compress is within the range `[0, modulus)`.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct AssertLtColsBytes<T, const N: usize> {
    /// Boolean flags to indicate the first byte in which the compress is smaller than the modulus.
    pub(crate) byte_flags: [T; N],

    pub(crate) a_comparison_byte: T,
    pub(crate) b_comparison_byte: T,
}

impl<F: Field, const N: usize> AssertLtColsBytes<F, N> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, a: &[u8], b: &[u8]) {
        let mut byte_flags = vec![0u8; N];

        for (a_byte, b_byte, flag) in
            izip!(a.iter().rev(), b.iter().rev(), byte_flags.iter_mut().rev())
        {
            assert!(a_byte <= b_byte);
            if a_byte < b_byte {
                *flag = 1;
                self.a_comparison_byte = F::from_canonical_u8(*a_byte);
                self.b_comparison_byte = F::from_canonical_u8(*b_byte);
                record.add_byte_lookup_event(ByteLookupEvent {
                    opcode: ByteOpcode::LTU,
                    a1: 1,
                    a2: 0,
                    b: *a_byte,
                    c: *b_byte,
                });
                break;
            }
        }

        for (byte, flag) in izip!(byte_flags.iter(), self.byte_flags.iter_mut()) {
            *flag = F::from_canonical_u8(*byte);
        }
    }
}

impl<V: Copy, const N: usize> AssertLtColsBytes<V, N> {
    pub fn eval<
        F: Field,
        CB: ChipBuilder<F, Var = V>,
        Ea: Into<CB::Expr> + Clone,
        Eb: Into<CB::Expr> + Clone,
    >(
        &self,
        builder: &mut CB,
        a: &[Ea],
        b: &[Eb],
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
    {
        // The byte flags give a specification of which byte is `first_eq`, i,e, the first most
        // significant byte for which the element `a` is smaller than `b`. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_eq` the element `a` byte is equal to the `b` byte.
        // * For the `first_eq` byte the `a`` byte is smaller than the `b`byte.
        // * all byte flags are boolean.
        // * only one byte flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verrify that only one flag is set to one.
        let mut sum_flags: CB::Expr = CB::Expr::ZERO;
        for &flag in self.byte_flags.iter() {
            // Assert that the flag is boolean.
            builder.assert_bool(flag);
            // Add the flag to the sum.
            sum_flags += flag.into();
        }
        // Assert that the sum is equal to one.
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bytes from
        // most significant until the first inequality.
        let mut is_inequality_visited = CB::Expr::ZERO;

        // The bytes of the modulus.

        let a: [CB::Expr; N] = core::array::from_fn(|i| a[i].clone().into());
        let b: [CB::Expr; N] = core::array::from_fn(|i| b[i].clone().into());

        let mut first_lt_byte = CB::Expr::ZERO;
        let mut b_comparison_byte = CB::Expr::ZERO;
        for (a_byte, b_byte, &flag) in
            izip!(a.iter().rev(), b.iter().rev(), self.byte_flags.iter().rev())
        {
            // Once the byte flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited += flag.into();

            first_lt_byte += a_byte.clone() * flag;
            b_comparison_byte += b_byte.clone() * flag;

            builder
                .when_not(is_inequality_visited.clone())
                .when(is_real.clone())
                .assert_eq(a_byte.clone(), b_byte.clone());
        }

        builder
            .when(is_real.clone())
            .assert_eq(self.a_comparison_byte, first_lt_byte);
        builder
            .when(is_real.clone())
            .assert_eq(self.b_comparison_byte, b_comparison_byte);

        // Send the comparison interaction.
        builder.looking_byte(
            ByteOpcode::LTU.as_field::<CB::F>(),
            CB::F::ONE,
            self.a_comparison_byte,
            self.b_comparison_byte,
            is_real,
        )
    }
}

/// Gadget columns for verifying that an element is within the range `[0, modulus)`.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct AssertLtColsBits<T, const N: usize> {
    /// Boolean flags to indicate the first byte in which the element is smaller than the modulus.
    pub(crate) bit_flags: [T; N],
}

impl<F: Field, const N: usize> AssertLtColsBits<F, N> {
    pub fn populate(&mut self, a: &[u32], b: &[u32]) {
        let mut bit_flags = vec![0u8; N];

        for (a_bit, b_bit, flag) in
            izip!(a.iter().rev(), b.iter().rev(), bit_flags.iter_mut().rev())
        {
            assert!(a_bit <= b_bit);
            debug_assert!(*a_bit == 0 || *a_bit == 1);
            debug_assert!(*b_bit == 0 || *b_bit == 1);
            if a_bit < b_bit {
                *flag = 1;
                break;
            }
        }

        for (bit, flag) in izip!(bit_flags.iter(), self.bit_flags.iter_mut()) {
            *flag = F::from_canonical_u8(*bit);
        }
    }
}

impl<V: Copy, const N: usize> AssertLtColsBits<V, N> {
    pub fn eval<
        F: Field,
        CB: ChipBuilder<F, Var = V>,
        Ea: Into<CB::Expr> + Clone,
        Eb: Into<CB::Expr> + Clone,
    >(
        &self,
        builder: &mut CB,
        a: &[Ea],
        b: &[Eb],
        is_real: impl Into<CB::Expr> + Clone,
    ) where
        V: Into<CB::Expr>,
    {
        // The bit flags give a specification of which bit is `first_lt`, i,e, the first most
        // significant bit for which the element `a` is smaller than `b`. To verify the
        // less-than claim we need to check that:
        // * For all bytes until `first_lt` the element `a` byte is equal to the `b` byte.
        // * For the `first_lt` bit the `a`` bit is smaller than the `b` bit.
        // * all bit flags are boolean.
        // * only one bit flag is set to one, and the rest are set to zero.

        // Check the flags are of valid form.

        // Verrify that only one flag is set to one.
        let mut sum_flags: CB::Expr = CB::Expr::ZERO;
        for &flag in self.bit_flags.iter() {
            // Assert that the flag is boolean.
            builder.assert_bool(flag);
            // Add the flag to the sum.
            sum_flags += flag.into();
        }
        // Assert that the sum is equal to one.
        builder.when(is_real.clone()).assert_one(sum_flags);

        // Check the less-than condition.

        // A flag to indicate whether an equality check is necessary (this is for all bits from
        // most significant until the first inequality.
        let mut is_inequality_visited = CB::Expr::ZERO;

        // The bits of the elements.
        let a: [CB::Expr; N] = core::array::from_fn(|i| a[i].clone().into());
        let b: [CB::Expr; N] = core::array::from_fn(|i| b[i].clone().into());

        // Calculate the bit which is the first inequality.
        let mut a_comparison_bit = CB::Expr::ZERO;
        let mut b_comparison_bit = CB::Expr::ZERO;
        for (a_bit, b_bit, &flag) in
            izip!(a.iter().rev(), b.iter().rev(), self.bit_flags.iter().rev())
        {
            // Once the bit flag was set to one, we turn off the quality check flag.
            // We can do this by calculating the sum of the flags since only `1` is set to `1`.
            is_inequality_visited += flag.into();

            a_comparison_bit += a_bit.clone() * flag;
            b_comparison_bit += b_bit.clone() * flag;

            builder
                .when(is_real.clone())
                .when_not(is_inequality_visited.clone())
                .assert_eq(a_bit.clone(), b_bit.clone());
        }

        builder
            .when(is_real.clone())
            .assert_eq(a_comparison_bit, CB::F::ZERO);
        builder
            .when(is_real.clone())
            .assert_eq(b_comparison_bit, CB::F::ONE);
    }
}
