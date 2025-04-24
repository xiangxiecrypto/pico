use crate::configs::config::FieldGenericConfig;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;

#[derive(Debug, Clone, Default)]
pub struct BabyBearSimple;

impl FieldGenericConfig for BabyBearSimple {
    type N = BabyBear;
    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
}
