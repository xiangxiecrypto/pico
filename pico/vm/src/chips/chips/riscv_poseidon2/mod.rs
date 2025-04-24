//! And AIR for the Poseidon2 permutation.
extern crate alloc;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants, configs::config::Poseidon2Config,
    machine::field::FieldSpecificPoseidon2Config,
};
use p3_field::Field;
use std::marker::PhantomData;

pub mod constraints;
pub mod event;
pub mod traces;

pub use event::Poseidon2Event;

pub type FieldSpecificPoseidon2Chip<F> = Poseidon2ChipP3<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    <F as FieldSpecificPoseidon2Config>::Poseidon2Config,
>;

/// A "vectorized" version of Poseidon2Air, for computing multiple Poseidon2 permutations per row.
pub struct Poseidon2ChipP3<F, LinearLayers, Config: Poseidon2Config> {
    pub(crate) constants: RoundConstants<F, Config>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<F: Field, LinearLayers, Config: Poseidon2Config> Default
    for Poseidon2ChipP3<F, LinearLayers, Config>
{
    fn default() -> Self {
        let constants = RoundConstants::default();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
