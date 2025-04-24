use crate::{
    chips::trace::TraceBorrowMut,
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{
        builder::ChipBuilder,
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::{Field, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_derive::AlignedBorrow;
use std::{marker::PhantomData, mem::size_of, sync::Arc};

#[repr(C)]
#[derive(Debug, AlignedBorrow)]
pub struct AddLookingCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
}
const ADD_LOOKING_COLS: usize = size_of::<AddLookingCols<u8>>();

#[repr(C)]
#[derive(Debug, AlignedBorrow)]
pub struct AddLookedCols<T> {
    pub a: T,
    pub b: T,
    pub result: T,
}

const ADD_LOOKED_COLS: usize = size_of::<AddLookedCols<u8>>();

#[derive(Debug, Default)]
pub struct AddLookingChip<F>(PhantomData<F>);

impl<F: PrimeField32> ChipBehavior<F> for AddLookingChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Add Looking Chip".to_string()
    }

    fn generate_main(&self, _: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // because of just test lookup feature, hardcode test data instead of the inputs are not from emulation records
        let row_num = 8;

        let mut trace =
            RowMajorMatrix::new(vec![F::ZERO; ADD_LOOKING_COLS * row_num], ADD_LOOKING_COLS);
        let rows: &mut [AddLookingCols<F>] = trace.borrow_rows_mut::<AddLookingCols<F>>();
        rows.iter_mut().enumerate().for_each(|(i, row)| {
            let a = i as u32;
            let b = (i + 1) as u32;
            let c = a + b;
            row.a = F::from_canonical_u32(a);
            row.b = F::from_canonical_u32(b);
            row.result = F::from_canonical_u32(c);
        });
        trace
    }

    fn generate_preprocessed(&self, _program: &Program) -> Option<RowMajorMatrix<F>> {
        let record = EmulationRecord::new(Arc::new(Program::default()));
        Some(self.generate_main(&record, &mut EmulationRecord::default()))
    }
    fn preprocessed_width(&self) -> usize {
        3
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<F: Field> BaseAir<F> for AddLookingChip<F> {
    fn width(&self) -> usize {
        ADD_LOOKING_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F, CB> Air<CB> for AddLookingChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, _next) = (main.row_slice(0), main.row_slice(1));
        let local: &AddLookingCols<CB::Var> = (*local).borrow();

        // no constraints for main trace, addition result is constrained by lookup
        builder.looking(SymbolicLookup::new(
            vec![local.a.into(), local.b.into(), local.result.into()],
            F::ONE.into(),
            LookupType::Byte,
            LookupScope::Regional,
        ))
    }
}

#[derive(Debug, Default)]
pub struct AddLookedChip<F>(PhantomData<F>);

impl<F: PrimeField32> ChipBehavior<F> for AddLookedChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Add Looked Chip".to_string()
    }

    fn generate_main(&self, _input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // because of just test lookup feature, hardcode test data instead of the inputs are not from emulation records
        let row_num = 8;

        let mut trace =
            RowMajorMatrix::new(vec![F::ZERO; ADD_LOOKING_COLS * row_num], ADD_LOOKING_COLS);
        let rows: &mut [AddLookedCols<F>] = trace.borrow_rows_mut::<AddLookedCols<F>>();
        rows.iter_mut().enumerate().for_each(|(i, row)| {
            let a = i as u32;
            let b = (i + 1) as u32;
            let c = a + b;
            row.a = F::from_canonical_u32(a);
            row.b = F::from_canonical_u32(b);
            row.result = F::from_canonical_u32(c);
        });
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<F: Field> BaseAir<F> for AddLookedChip<F> {
    fn width(&self) -> usize {
        ADD_LOOKED_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F, CB> Air<CB> for AddLookedChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, _) = (main.row_slice(0), main.row_slice(1));
        let local: &AddLookedCols<CB::Var> = (*local).borrow();

        // add a+b constraint
        let result = local.a + local.b;
        builder.assert_eq(result, local.result);

        builder.looked(SymbolicLookup::new(
            vec![local.a.into(), local.b.into(), local.result.into()],
            F::ONE.into(),
            LookupType::Byte,
            LookupScope::Regional,
        ))
    }
}
