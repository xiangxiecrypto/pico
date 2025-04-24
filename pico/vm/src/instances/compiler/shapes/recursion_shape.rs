use crate::{
    chips::chips::{
        alu_base::BaseAluChip,
        alu_ext::ExtAluChip,
        batch_fri::BatchFRIChip,
        exp_reverse_bits::ExpReverseBitsLenChip,
        poseidon2::POSEIDON2_CHIPNAME,
        public_values::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        recursion_memory::{constant::MemoryConstChip, variable::MemoryVarChip},
        select::SelectChip,
    },
    compiler::recursion::program::RecursionProgram,
    instances::{chiptype::recursion_chiptype::RecursionChipType, compiler::shapes::ProofShape},
    machine::{chip::ChipBehavior, field::FieldSpecificPoseidon2Config},
    primitives::consts::EXTENSION_DEGREE,
};
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_util::log2_ceil_usize;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RiscvRecursionShape {
    pub proof_shapes: Vec<ProofShape>,
    pub is_complete: bool,
}

impl From<ProofShape> for RiscvRecursionShape {
    fn from(proof_shape: ProofShape) -> Self {
        Self {
            proof_shapes: vec![proof_shape],
            is_complete: false,
        }
    }
}

/// The shape of the compress proof with vk validation proofs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursionVkShape {
    pub recursion_shape: RecursionShape,
    pub merkle_tree_height: usize,
}

impl RecursionVkShape {
    pub fn from_proof_shapes(proof_shapes: Vec<ProofShape>, height: usize) -> Self {
        Self {
            recursion_shape: proof_shapes.into(),
            merkle_tree_height: height,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecursionShape {
    pub proof_shapes: Vec<ProofShape>,
}

impl From<Vec<ProofShape>> for RecursionShape {
    fn from(proof_shapes: Vec<ProofShape>) -> Self {
        Self { proof_shapes }
    }
}

pub struct RecursionShapeConfig<F, A> {
    allowed_shapes: Vec<HashMap<String, usize>>,
    _marker: PhantomData<(F, A)>,
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config>
    Default for RecursionShapeConfig<F, RecursionChipType<F>>
where
    RecursionChipType<F>: ChipBehavior<F>,
{
    fn default() -> Self {
        let mem_const = RecursionChipType::<F>::MemoryConst(MemoryConstChip::default()).name();
        let mem_var = RecursionChipType::<F>::MemoryVar(MemoryVarChip::default()).name();
        let base_alu = RecursionChipType::<F>::BaseAlu(BaseAluChip::default()).name();
        let ext_alu = RecursionChipType::<F>::ExtAlu(ExtAluChip::default()).name();

        let poseidon2 = POSEIDON2_CHIPNAME.to_string();
        let exp_reverse_bits_len =
            RecursionChipType::<F>::ExpReverseBitsLen(ExpReverseBitsLenChip::default()).name();

        let public_values =
            RecursionChipType::<F>::PublicValues(PublicValuesChip::default()).name();
        let batch_fri = RecursionChipType::<F>::BatchFRI(BatchFRIChip::default()).name();
        let select = RecursionChipType::<F>::Select(SelectChip::default()).name();

        // Specify allowed shapes.
        let allowed_shapes = [
            // maximal recursion shape, must be sufficient for all risc-v shape verification
            [
                (ext_alu.clone(), 17),
                (base_alu.clone(), 18),
                (mem_var.clone(), 19),
                (poseidon2.clone(), 18),
                (mem_const.clone(), 19),
                (batch_fri.clone(), 21),
                (exp_reverse_bits_len.clone(), 19),
                (select.clone(), 19),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // combine shape
            [
                (mem_const.clone(), 18),
                (mem_var.clone(), 17),
                (base_alu.clone(), 17),
                (ext_alu.clone(), 16),
                (poseidon2.clone(), 17),
                (batch_fri.clone(), 18),
                (select.clone(), 18),
                (exp_reverse_bits_len.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // combine shape
            [
                (mem_const.clone(), 18),
                (mem_var.clone(), 18),
                (base_alu.clone(), 17),
                (ext_alu.clone(), 16),
                (poseidon2.clone(), 17),
                (batch_fri.clone(), 18),
                (select.clone(), 18),
                (exp_reverse_bits_len.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            // convert shape
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 17),
                (mem_var.clone(), 18),
                (poseidon2.clone(), 17),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 20),
                (exp_reverse_bits_len.clone(), 17),
                (select.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 17),
                (mem_var.clone(), 18),
                (poseidon2.clone(), 17),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 19),
                (exp_reverse_bits_len.clone(), 17),
                (select.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 17),
                (mem_var.clone(), 18),
                (poseidon2.clone(), 16),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 20),
                (exp_reverse_bits_len.clone(), 17),
                (select.clone(), 18),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (ext_alu.clone(), 16),
                (base_alu.clone(), 17),
                (mem_var.clone(), 18),
                (poseidon2.clone(), 17),
                (mem_const.clone(), 18),
                (batch_fri.clone(), 20),
                (exp_reverse_bits_len.clone(), 17),
                (select.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (mem_const.clone(), 17),
                (mem_var.clone(), 17),
                (base_alu.clone(), 16),
                (ext_alu.clone(), 16),
                (poseidon2.clone(), 16),
                (batch_fri.clone(), 19),
                (select.clone(), 17),
                (exp_reverse_bits_len.clone(), 17),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
            [
                (mem_const.clone(), 17),
                (mem_var.clone(), 18),
                (base_alu.clone(), 16),
                (ext_alu.clone(), 16),
                (poseidon2.clone(), 17),
                (batch_fri.clone(), 20),
                (select.clone(), 17),
                (exp_reverse_bits_len.clone(), 16),
                (public_values.clone(), PUB_VALUES_LOG_HEIGHT),
            ],
        ]
        .map(HashMap::from)
        .to_vec();
        Self {
            allowed_shapes,
            _marker: PhantomData,
        }
    }
}

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + FieldSpecificPoseidon2Config>
    RecursionShapeConfig<F, RecursionChipType<F>>
{
    pub fn get_all_shape_combinations(
        &self,
        batch_size: usize,
    ) -> impl Iterator<Item = Vec<ProofShape>> + '_ {
        (0..batch_size)
            .map(|_| {
                self.allowed_shapes
                    .iter()
                    .cloned()
                    .map(|map| map.into_iter().collect::<ProofShape>())
            })
            .multi_cartesian_product()
    }

    // Get the allowed shape with a minimal hamming distance from the current shape.
    pub fn padding_shape(&self, program: &mut RecursionProgram<F>) {
        let heights = RecursionChipType::<F>::chip_heights(program);
        let mut min_distance = usize::MAX;
        let mut closest_shape = None;
        for shape in self.allowed_shapes.iter() {
            let mut distance = 0;
            let mut is_valid = true;
            for (name, height) in heights.iter() {
                let next_power_of_two = height.next_power_of_two();
                let allowed_log_height = shape.get(name).unwrap();
                let allowed_height: usize = 1 << allowed_log_height;
                if next_power_of_two != allowed_height {
                    distance += 1;
                }
                if next_power_of_two > allowed_height {
                    is_valid = false;
                }
            }
            if is_valid && distance < min_distance {
                min_distance = distance;
                closest_shape = Some(shape.clone());
            }
        }

        if let Some(shape) = closest_shape {
            let shape = RecursionPadShape { inner: shape };

            for (chip_name, height) in heights.iter() {
                if shape.inner.contains_key(chip_name) {
                    debug!(
                        "Chip {:<20}: {:<3} -> {:<3}",
                        chip_name,
                        log2_ceil_usize(*height),
                        shape.inner[chip_name],
                    );
                } else {
                    warn!(
                        "Unexpected: Chip {} not found in shape, log size: {}",
                        chip_name,
                        log2_ceil_usize(*height)
                    );
                }
            }

            program.shape = Some(shape);
        } else {
            let mut heights_log_sizes = String::new();
            for (chip_name, height) in heights.iter() {
                heights_log_sizes.push_str(&format!(
                    "Chip: {}, Log Size: {}\n",
                    chip_name,
                    log2_ceil_usize(*height)
                ));
            }

            panic!(
                "No shape found for heights. Heights log sizes:\n{}",
                heights_log_sizes
            );
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecursionPadShape {
    pub(crate) inner: HashMap<String, usize>,
}
