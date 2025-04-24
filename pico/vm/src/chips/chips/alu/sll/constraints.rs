use std::borrow::Borrow;

use super::{columns::ShiftLeftCols, traces::SLLChip, ShiftLeftValueCols};
use crate::{
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{BYTE_SIZE, WORD_SIZE},
};
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;

impl<F: Field, CB> Air<CB> for SLLChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ShiftLeftCols<CB::Var> = (*local).borrow();

        let zero: CB::Expr = CB::F::ZERO.into();
        let one: CB::Expr = CB::F::ONE.into();
        let base: CB::Expr = CB::F::from_canonical_u32(1 << BYTE_SIZE).into();

        for ShiftLeftValueCols {
            a,
            b,
            c,
            c_lsb,
            shift_by_n_bits,
            bit_shift_multiplier,
            shift_result,
            shift_result_carry,
            shift_by_n_bytes,
            is_real,
        } in local.values
        {
            // Check the sum of c_lsb[i] * 2^i equals c[0].
            let mut c_byte_sum = zero.clone();
            for i in 0..BYTE_SIZE {
                let val: CB::Expr = F::from_canonical_u32(1 << i).into();
                c_byte_sum += val * c_lsb[i];
            }
            builder.assert_eq(c_byte_sum, c[0]);

            // Check shift_by_n_bits[i] is 1 if i = num_bits_to_shift.
            let mut num_bits_to_shift = zero.clone();

            //  num_bits_to_shift = event.c as usize % BYTE_SIZE, so the maximum value of num_bits_to_shift is 7, just need 3 bits to calculate this.
            for i in 0..3 {
                num_bits_to_shift += c_lsb[i] * F::from_canonical_u32(1 << i);
            }
            // check num_bits_to_shift i'th is 1
            for i in 0..BYTE_SIZE {
                builder
                    .when(shift_by_n_bits[i])
                    .assert_eq(num_bits_to_shift.clone(), F::from_canonical_usize(i));
            }

            // Check bit_shift_multiplier = 2^num_bits_to_shift by using shift_by_n_bits.
            for i in 0..BYTE_SIZE {
                builder
                    .when(shift_by_n_bits[i])
                    .assert_eq(bit_shift_multiplier, F::from_canonical_usize(1 << i));
            }

            // Check bit_shift_result = b * bit_shift_multiplier by using bit_shift_result_carry to
            // carry-propagate.
            for i in 0..WORD_SIZE {
                let mut v = b[i] * bit_shift_multiplier - shift_result_carry[i] * base.clone();
                if i > 0 {
                    v += shift_result_carry[i - 1].into();
                }
                builder.assert_eq(shift_result[i], v);
            }

            //  num_bytes_to_shift = (event.c & 0b11111) as usize / BYTE_SIZE; use the c_lsb 4th and 5th presents the byte shift number
            let num_bytes_to_shift = c_lsb[3] + c_lsb[4] * F::from_canonical_u32(2);

            // Verify that shift_by_n_bytes[i] = 1 if and only if i = num_bytes_to_shift.
            for i in 0..WORD_SIZE {
                builder
                    .when(shift_by_n_bytes[i])
                    .assert_eq(num_bytes_to_shift.clone(), F::from_canonical_usize(i));
            }

            // The bytes of a must match those of bit_shift_result, taking into account the byte
            // shifting.
            for shift_size in 0..WORD_SIZE {
                let mut shifting = builder.when(shift_by_n_bytes[shift_size]);
                for i in 0..WORD_SIZE {
                    if i < shift_size {
                        // The first num_bytes_to_shift bytes must be zero.
                        shifting.assert_eq(a[i], zero.clone());
                    } else {
                        shifting.assert_eq(a[i], shift_result[i - shift_size]);
                    }
                }
            }

            for bit in c_lsb.iter() {
                builder.assert_bool(*bit);
            }

            for shift in shift_by_n_bits.iter() {
                builder.assert_bool(*shift);
            }
            builder.assert_eq(
                shift_by_n_bits.iter().fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );

            for shift in shift_by_n_bytes.iter() {
                builder.assert_bool(*shift);
            }

            builder.assert_eq(
                shift_by_n_bytes
                    .iter()
                    .fold(zero.clone(), |acc, &x| acc + x),
                one.clone(),
            );

            builder.assert_bool(is_real);

            // range check
            builder.slice_range_check_u8(&shift_result, is_real);
            builder.slice_range_check_u8(&shift_result_carry, is_real);

            builder.looked_alu(F::from_canonical_u32(Opcode::SLL as u32), a, b, c, is_real);
        }
    }
}
