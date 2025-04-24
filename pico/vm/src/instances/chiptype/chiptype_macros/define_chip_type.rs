#[macro_export]
macro_rules! define_chip_type {
    (
        $enum_name:ident<$F:ident>,
        [ $( ($variant:ident, $chip_type:ident) ),+ ]
    ) => {
        pub enum $enum_name<$F: PrimeField32 + $crate::machine::field::FieldSpecificPoseidon2Config> {
            $(
                $variant($crate::enum_chip_type!($variant, $chip_type<$F>)),
            )+
        }

        $crate::impl_chip_behavior!($enum_name, $F, [ $( ($variant, $chip_type) ),+ ]);

        $crate::impl_base_air!($enum_name, $F, [ $( ($variant, $chip_type) ),+ ]);

        $crate::impl_air!($enum_name, $F, [ $( ($variant, $chip_type) ),+ ]);
    };
}
