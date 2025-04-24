use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
};
use std::fmt::Debug;

use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryReadCols, MemoryReadWriteCols},
        },
        gadgets::{
            curves::{
                weierstrass::{
                    bls381::{bls12381_sqrt, Bls12381},
                    secp256k1::{secp256k1_sqrt, Secp256k1},
                    WeierstrassParameters,
                },
                CurveType, EllipticCurve,
            },
            field::{
                field_lt::FieldLtCols,
                field_op::{FieldOpCols, FieldOperation},
                field_sqrt::FieldSqrtCols,
            },
            utils::{
                conversions::{bytes_to_words_le_vec, limbs_from_access, limbs_from_prev_access},
                field_params::{limbs_from_slice, FieldParameters, NumLimbs, NumWords},
                limbs::Limbs,
            },
        },
        utils::pad_rows_fixed,
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{precompiles::PrecompileEvent, SyscallCode},
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
    },
};
use hybrid_array::Array;
use num::{BigUint, Zero};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use std::marker::PhantomData;
use typenum::Unsigned;

pub const fn num_weierstrass_decompress_cols<P: FieldParameters + NumWords>() -> usize {
    size_of::<WeierstrassDecompressCols<u8, P>>()
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct WeierstrassDecompressCols<T, P: FieldParameters + NumWords> {
    pub is_real: T,
    pub chunk: T,
    pub clk: T,
    pub ptr: T,
    pub sign_bit: T,
    pub x_access: Array<MemoryReadCols<T>, P::WordsFieldElement>,
    pub y_access: Array<MemoryReadWriteCols<T>, P::WordsFieldElement>,
    pub(crate) range_x: FieldLtCols<T, P>,
    pub(crate) x_2: FieldOpCols<T, P>,
    pub(crate) x_3: FieldOpCols<T, P>,
    pub(crate) x_3_plus_b: FieldOpCols<T, P>,
    pub(crate) y: FieldSqrtCols<T, P>,
    pub(crate) neg_y: FieldOpCols<T, P>,
}

/// A set of columns to compute `WeierstrassDecompress` that decompresses a point on a Weierstrass
/// curve.
#[derive(Debug, Clone, AlignedBorrow)]
#[repr(C)]
pub struct LexicographicChoiceCols<T, P: FieldParameters + NumWords> {
    pub comparison_lt_cols: FieldLtCols<T, P>,
    pub neg_y_range_check: FieldLtCols<T, P>,
    pub is_y_eq_sqrt_y_result: T,
    pub when_sqrt_y_res_is_lt: T,
    pub when_neg_y_res_is_lt: T,
}

/// The convention for choosing the decompressed `y` value given a sign bit.
pub enum SignChoiceRule {
    /// Lease significant bit convention.
    ///
    /// In this convention, the `sign_bit` matches the pairty of the `y` value. This is the
    /// convention used in the ECDSA signature scheme, for example, in the secp256k1 curve.
    LeastSignificantBit,
    /// Lexicographic convention.
    ///
    /// In this convention, the `sign_bit` corresponds to whether the `y` value is larger than its
    /// negative counterpart with respect to the embedding of ptime field elements as integers.
    /// This onvention used in the BLS signature scheme, for example, in the BLS12-381 curve.
    Lexicographic,
}

#[allow(clippy::type_complexity)]
pub struct WeierstrassDecompressChip<F, E> {
    sign_rule: SignChoiceRule,
    _marker: PhantomData<fn(F, E) -> (F, E)>,
}

impl<F> Default for WeierstrassDecompressChip<F, Bls12381> {
    fn default() -> Self {
        Self::with_lexicographic_rule()
    }
}

impl<F> Default for WeierstrassDecompressChip<F, Secp256k1> {
    fn default() -> Self {
        Self::with_lsb_rule()
    }
}

impl<F, E> WeierstrassDecompressChip<F, E> {
    pub const fn new(sign_rule: SignChoiceRule) -> Self {
        Self {
            sign_rule,
            _marker: PhantomData,
        }
    }

    pub const fn with_lsb_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::LeastSignificantBit,
            _marker: PhantomData,
        }
    }

    pub const fn with_lexicographic_rule() -> Self {
        Self {
            sign_rule: SignChoiceRule::Lexicographic,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> WeierstrassDecompressChip<F, E> {
    fn populate_field_ops(
        blu_events: &mut impl ByteRecordBehavior,
        cols: &mut WeierstrassDecompressCols<F, E::BaseField>,
        x: BigUint,
    ) {
        // Y = sqrt(x^3 + b)
        cols.range_x
            .populate(blu_events, &x, &E::BaseField::modulus());
        let x_2 = cols
            .x_2
            .populate(blu_events, &x.clone(), &x.clone(), FieldOperation::Mul);
        let x_3 = cols.x_3.populate(blu_events, &x_2, &x, FieldOperation::Mul);
        let b = E::b_int();
        let x_3_plus_b = cols
            .x_3_plus_b
            .populate(blu_events, &x_3, &b, FieldOperation::Add);

        let sqrt_fn = match E::CURVE_TYPE {
            CurveType::Bls12381 => bls12381_sqrt,
            CurveType::Secp256k1 => secp256k1_sqrt,
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };
        let y = cols.y.populate(blu_events, &x_3_plus_b, sqrt_fn);

        let zero = BigUint::zero();
        cols.neg_y
            .populate(blu_events, &zero, &y, FieldOperation::Sub);
    }
}

impl<F: PrimeField32, E: EllipticCurve + WeierstrassParameters> ChipBehavior<F>
    for WeierstrassDecompressChip<F, E>
{
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        match E::CURVE_TYPE {
            CurveType::Secp256k1 => "Secp256k1Decompress".to_string(),
            CurveType::Bls12381 => "Bls12381Decompress".to_string(),
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        }
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = match E::CURVE_TYPE {
            CurveType::Secp256k1 => input.get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS),
            CurveType::Bls12381 => input.get_precompile_events(SyscallCode::BLS12381_DECOMPRESS),
            _ => panic!("Unsupported curve"),
        };

        let mut rows = Vec::new();
        let weierstrass_width = num_weierstrass_decompress_cols::<E::BaseField>();
        let width = BaseAir::<F>::width(self);

        let mut new_byte_lookup_events = Vec::new();

        let modulus = E::BaseField::modulus();

        for i in 0..events.len() {
            let (_syscall_event, precompile_event) = &events[i];

            let event = match precompile_event {
                PrecompileEvent::Secp256k1Decompress(event)
                | PrecompileEvent::Bls12381Decompress(event) => event,
                _ => unreachable!(),
            };

            let mut row = vec![F::ZERO; width];
            let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                row[0..weierstrass_width].borrow_mut();

            cols.is_real = F::from_bool(true);
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.ptr = F::from_canonical_u32(event.ptr);
            cols.sign_bit = F::from_bool(event.sign_bit);

            let x = BigUint::from_bytes_le(&event.x_bytes);
            Self::populate_field_ops(&mut new_byte_lookup_events, cols, x);

            for i in 0..cols.x_access.len() {
                cols.x_access[i].populate(event.x_memory_records[i], &mut new_byte_lookup_events);
            }
            for i in 0..cols.y_access.len() {
                cols.y_access[i]
                    .populate_write(event.y_memory_records[i], &mut new_byte_lookup_events);
            }

            if matches!(self.sign_rule, SignChoiceRule::Lexicographic) {
                let lsb = cols.y.lsb;
                let choice_cols: &mut LexicographicChoiceCols<F, E::BaseField> =
                    row[weierstrass_width..width].borrow_mut();

                let decompressed_y = BigUint::from_bytes_le(&event.decompressed_y_bytes);
                let neg_y = &modulus - &decompressed_y;

                let is_y_eq_sqrt_y_result =
                    F::from_canonical_u8(event.decompressed_y_bytes[0] % 2) == lsb;
                choice_cols.is_y_eq_sqrt_y_result = F::from_bool(is_y_eq_sqrt_y_result);

                if is_y_eq_sqrt_y_result {
                    choice_cols.neg_y_range_check.populate(
                        &mut new_byte_lookup_events,
                        &neg_y,
                        &modulus,
                    );
                } else {
                    choice_cols.neg_y_range_check.populate(
                        &mut new_byte_lookup_events,
                        &decompressed_y,
                        &modulus,
                    );
                }
                if event.sign_bit {
                    assert!(neg_y < decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &neg_y,
                        &decompressed_y,
                    );
                } else {
                    assert!(neg_y > decompressed_y);
                    choice_cols.when_sqrt_y_res_is_lt = F::from_bool(is_y_eq_sqrt_y_result);
                    choice_cols.when_neg_y_res_is_lt = F::from_bool(!is_y_eq_sqrt_y_result);
                    choice_cols.comparison_lt_cols.populate(
                        &mut new_byte_lookup_events,
                        &decompressed_y,
                        &neg_y,
                    );
                }
            }

            rows.push(row);
        }
        output.add_byte_lookup_events(new_byte_lookup_events);

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(
            &mut rows,
            || {
                let mut row = vec![F::ZERO; width];
                let cols: &mut WeierstrassDecompressCols<F, E::BaseField> =
                    row.as_mut_slice()[0..weierstrass_width].borrow_mut();

                // take X of the generator as a dummy value to make sure Y^2 = X^3 + b holds
                let dummy_value = E::generator().0;
                let dummy_bytes = dummy_value.to_bytes_le();
                let words = bytes_to_words_le_vec(&dummy_bytes);
                for i in 0..cols.x_access.len() {
                    cols.x_access[i].access.value = words[i].into();
                }

                Self::populate_field_ops(&mut vec![], cols, dummy_value);
                row
            },
            log_rows,
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect::<Vec<_>>(), width)
    }

    fn is_active(&self, chunk: &Self::Record) -> bool {
        if let Some(shape) = chunk.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            match E::CURVE_TYPE {
                CurveType::Secp256k1 => !chunk
                    .get_precompile_events(SyscallCode::SECP256K1_DECOMPRESS)
                    .is_empty(),
                CurveType::Bls12381 => !chunk
                    .get_precompile_events(SyscallCode::BLS12381_DECOMPRESS)
                    .is_empty(),
                _ => panic!("Unsupported curve"),
            }
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, E: EllipticCurve> BaseAir<F> for WeierstrassDecompressChip<F, E> {
    fn width(&self) -> usize {
        num_weierstrass_decompress_cols::<E::BaseField>()
            + match self.sign_rule {
                SignChoiceRule::LeastSignificantBit => 0,
                SignChoiceRule::Lexicographic => {
                    size_of::<LexicographicChoiceCols<u8, E::BaseField>>()
                }
            }
    }
}

impl<F: PrimeField32, CB, E: EllipticCurve + WeierstrassParameters> Air<CB>
    for WeierstrassDecompressChip<F, E>
where
    F: Field,
    CB: ChipBuilder<F>,
    Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs>: Copy,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        let weierstrass_cols = num_weierstrass_decompress_cols::<E::BaseField>();
        let local_slice = main.row_slice(0);
        let local: &WeierstrassDecompressCols<CB::Var, E::BaseField> =
            (*local_slice)[0..weierstrass_cols].borrow();

        let num_limbs = <E::BaseField as NumLimbs>::Limbs::USIZE;
        let num_words_field_element = num_limbs / 4;

        builder.assert_bool(local.sign_bit);

        let x: Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_prev_access(&local.x_access);
        let max_num_limbs = E::BaseField::to_limbs_field_slice(&E::BaseField::modulus());
        local.range_x.eval(
            builder,
            &x,
            &limbs_from_slice::<CB::Expr, <E::BaseField as NumLimbs>::Limbs, CB::F>(max_num_limbs),
            local.is_real,
        );
        local
            .x_2
            .eval(builder, &x, &x, FieldOperation::Mul, local.is_real);
        local.x_3.eval(
            builder,
            &local.x_2.result,
            &x,
            FieldOperation::Mul,
            local.is_real,
        );
        let b = E::b_int();
        let b_const = E::BaseField::to_limbs_field::<CB::F, _>(&b);
        local.x_3_plus_b.eval(
            builder,
            &local.x_3.result,
            &b_const,
            FieldOperation::Add,
            local.is_real,
        );

        local.neg_y.eval(
            builder,
            &[CB::Expr::ZERO].iter(),
            &local.y.multiplication.result,
            FieldOperation::Sub,
            local.is_real,
        );

        local.y.eval(
            builder,
            &local.x_3_plus_b.result,
            local.y.lsb,
            local.is_real,
        );

        let y_limbs: Limbs<CB::Var, <E::BaseField as NumLimbs>::Limbs> =
            limbs_from_access(&local.y_access);

        // Constrain the y value according the sign rule convention.
        match self.sign_rule {
            SignChoiceRule::LeastSignificantBit => {
                // When the sign rule is LeastSignificantBit, the sign_bit should match the parity
                // of the result. The parity of the square root result is given by the local.y.lsb
                // value. Thus, if the sign_bit matches the local.y.lsb value, then the result
                // should be the square root of the y value. Otherwise, the result should be the
                // negative square root of the y value.
                builder
                    .when(local.is_real)
                    .when_ne(local.y.lsb, CB::Expr::ONE - local.sign_bit)
                    .assert_all_eq(local.y.multiplication.result, y_limbs);
                builder
                    .when(local.is_real)
                    .when_ne(local.y.lsb, local.sign_bit)
                    .assert_all_eq(local.neg_y.result, y_limbs);
            }
            SignChoiceRule::Lexicographic => {
                // When the sign rule is Lexicographic, the sign_bit corresponds to whether
                // the result is greater than or less its negative with respect to the lexicographic
                // ordering, embedding prime field values as integers.
                //
                // In order to endorce these constraints, we will use the auxillary choice columns.

                // Get the choice columns from the row slice
                let choice_cols: &LexicographicChoiceCols<CB::Var, E::BaseField> = (*local_slice)
                    [weierstrass_cols
                        ..weierstrass_cols
                            + size_of::<LexicographicChoiceCols<u8, E::BaseField>>()]
                    .borrow();

                // Range check the neg_y value since we are now using a lexicographic comparison.
                let modulus_limbs = E::BaseField::to_limbs_field_slice(&E::BaseField::modulus());
                let modulus_limbs =
                    limbs_from_slice::<CB::Expr, <E::BaseField as NumLimbs>::Limbs, CB::F>(
                        modulus_limbs,
                    );
                choice_cols.neg_y_range_check.eval(
                    builder,
                    &local.neg_y.result,
                    &modulus_limbs,
                    local.is_real,
                );

                // Assert that the flags are booleans.
                builder.assert_bool(choice_cols.is_y_eq_sqrt_y_result);
                builder.assert_bool(choice_cols.when_sqrt_y_res_is_lt);
                builder.assert_bool(choice_cols.when_neg_y_res_is_lt);

                // Assert that the `when` flags are disjoint:
                builder.when(local.is_real).assert_one(
                    choice_cols.when_sqrt_y_res_is_lt + choice_cols.when_neg_y_res_is_lt,
                );

                // Assert that the value of `y` matches the claimed value by the flags.

                builder
                    .when(local.is_real)
                    .when(choice_cols.is_y_eq_sqrt_y_result)
                    .assert_all_eq(local.y.multiplication.result, y_limbs);

                builder
                    .when(local.is_real)
                    .when_not(choice_cols.is_y_eq_sqrt_y_result)
                    .assert_all_eq(local.neg_y.result, y_limbs);

                // Assert that the comparison only turns on when `is_real` is true.
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_sqrt_y_res_is_lt);
                builder
                    .when_not(local.is_real)
                    .assert_zero(choice_cols.when_neg_y_res_is_lt);

                // Assert that the flags are set correctly. When the sign_bit is true, we want that
                // `neg_y < y`, and vice versa when the sign_bit is false. Hence, when should have:
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                // - When `sign_bit` is true , then when_sqrt_y_res_is_lt = (y != sqrt(y)).
                // - When `sign_bit` is false, then when_neg_y_res_is_lt = (y == sqrt(y)).
                //
                // Since the when less-than flags are disjoint, we can assert that:
                // - When `sign_bit` is true , then is_y_eq_sqrt_y_result == when_neg_y_res_is_lt.
                // - When `sign_bit` is false, then is_y_eq_sqrt_y_result == when_sqrt_y_res_is_lt.
                builder.when(local.is_real).when(local.sign_bit).assert_eq(
                    choice_cols.is_y_eq_sqrt_y_result,
                    choice_cols.when_neg_y_res_is_lt,
                );
                builder
                    .when(local.is_real)
                    .when_not(local.sign_bit)
                    .assert_eq(
                        choice_cols.is_y_eq_sqrt_y_result,
                        choice_cols.when_sqrt_y_res_is_lt,
                    );

                // Assert the less-than comparisons according to the flags.

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.y.multiplication.result,
                    &local.neg_y.result,
                    choice_cols.when_sqrt_y_res_is_lt,
                );

                choice_cols.comparison_lt_cols.eval(
                    builder,
                    &local.neg_y.result,
                    &local.y.multiplication.result,
                    choice_cols.when_neg_y_res_is_lt,
                );
            }
        }

        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                local.ptr.into() + CB::F::from_canonical_u32((i as u32) * 4 + num_limbs as u32),
                &local.x_access[i],
                local.is_real,
            );
        }
        for i in 0..num_words_field_element {
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                local.ptr.into() + CB::F::from_canonical_u32((i as u32) * 4),
                &local.y_access[i],
                local.is_real,
            );
        }

        let syscall_id = match E::CURVE_TYPE {
            CurveType::Bls12381 => {
                CB::F::from_canonical_u32(SyscallCode::BLS12381_DECOMPRESS.syscall_id())
            }
            CurveType::Secp256k1 => {
                CB::F::from_canonical_u32(SyscallCode::SECP256K1_DECOMPRESS.syscall_id())
            }
            _ => panic!("Unsupported curve: {}", E::CURVE_TYPE),
        };

        builder.looked_syscall(
            local.clk,
            syscall_id,
            local.ptr,
            local.sign_bit,
            local.is_real,
        );
    }
}
