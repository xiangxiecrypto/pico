use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[derive(Default)]
pub struct MemoryLocalChip<F>(PhantomData<F>);
