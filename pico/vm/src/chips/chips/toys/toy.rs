//! Toy chip used for chip initialization tests

use crate::{
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::riscv::record::EmulationRecord,
    machine::{builder::ChipBuilder, chip::ChipBehavior, utils::pad_to_power_of_two},
};
use itertools::Itertools;
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use std::{marker::PhantomData, mem::size_of};

/// The number of main trace columns for `ToyChip`
pub const NUM_TOY_COLS: usize = size_of::<ToyCols<u8>>();

/// The name of toy chip
const TOY_CHIP_NAME: &str = "Toy";

/// A chip that implements a simple addition for two bytes.
#[derive(Debug, Default)]
pub struct ToyChip<F>(PhantomData<F>);

/// The column layout for toy chip
#[derive(Debug)]
pub struct ToyCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
    pub is_add: T,
}

impl<'a, T: Clone> ToyCols<&'a T> {
    fn new(a: &'a T, b: &'a T, result: &'a T, is_add: &'a T) -> Self {
        Self {
            a,
            b,
            result,
            is_add,
        }
    }

    fn to_row(&self) -> [T; NUM_TOY_COLS] {
        [self.a, self.b, self.result, self.is_add].map(Clone::clone)
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ToyChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        TOY_CHIP_NAME.to_string()
    }

    fn generate_preprocessed(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        // NOTE: It's not reasonable, just to enable testing.
        // `2048` is the column number equalled to main trace.
        Some(RowMajorMatrix::new(vec![F::ZERO; 2048], 1))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the rows for the trace.
        let merged_events = input
            .add_events
            .iter()
            .chain(input.sub_events.iter())
            .collect_vec();

        let rows = merged_events
            .iter()
            .flat_map(|event| {
                let [a, b, result, is_add] = match event.opcode {
                    Opcode::ADD => {
                        let a = event.a as u8;
                        let b = event.b as u8;
                        let [b, result] = match a.checked_add(b) {
                            Some(result) => [b, result],
                            None => [0, a],
                        };

                        [a, b, result, 1]
                    }
                    Opcode::SUB => {
                        let a = event.a as u8;
                        let b = event.b as u8;
                        let [b, result] = match a.checked_sub(b) {
                            Some(result) => [b, result],
                            None => [0, a],
                        };

                        [a, b, result, 0]
                    }
                    _ => unreachable!(),
                };

                let [a, b, result, is_add] = [a, b, result, is_add].map(F::from_canonical_u8);
                ToyCols::new(&a, &b, &result, &is_add).to_row()
            })
            .collect_vec();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(rows, NUM_TOY_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_TOY_COLS, F>(&mut trace.values, None);

        trace
    }

    fn preprocessed_width(&self) -> usize {
        1
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<F: Field> BaseAir<F> for ToyChip<F> {
    fn width(&self) -> usize {
        NUM_TOY_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F, CB> Air<CB> for ToyChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let row = main.row_slice(0);
        let local = ToyCols::new(&row[0], &row[1], &row[2], &row[3]);

        let one = CB::Expr::ONE;

        let [a, b, result, is_add] = [*local.a, *local.b, *local.result, *local.is_add];

        builder.assert_bool(is_add);
        builder.assert_zero(a + is_add * b - (one - is_add) * b - result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::FieldAlgebra;
    use rand::{thread_rng, Rng};
    use std::array;

    type F = BabyBear;

    #[test]
    fn test_toy_cols() {
        let rng = &mut thread_rng();

        let [a, b, result] = array::from_fn(|_| F::from_canonical_u8(rng.gen()));
        let is_add = F::from_bool(rng.gen());
        let cols = ToyCols::new(&a, &b, &result, &is_add);

        let mut expected_row = vec![a, b, result, is_add];
        pad_to_power_of_two::<NUM_TOY_COLS, F>(&mut expected_row, None);
        assert_eq!(cols.to_row(), [a, b, result, is_add]);
    }
}
