//! Lookup associating builder functions

use super::ChipBuilder;
use crate::{
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    configs::config::StarkGenericConfig,
    machine::{
        builder::{AirBuilder, FilteredAirBuilder},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use p3_field::{Field, FieldAlgebra};
use std::iter::once;

/// message builder for the chips.
pub trait LookupBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyLookupBuilder: AirBuilder {}

impl<AB: EmptyLookupBuilder, M> LookupBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

impl<SC: StarkGenericConfig> EmptyLookupBuilder for ProverConstraintFolder<SC> {}
impl<SC: StarkGenericConfig> EmptyLookupBuilder for VerifierConstraintFolder<'_, SC> {}
impl<F: Field, AB: AirBuilder<F = F>> EmptyLookupBuilder for FilteredAirBuilder<'_, AB> {}

pub trait ChipLookupBuilder<F: Field>: ChipBuilder<F> {
    /// Looking for an instruction to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_instruction(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Instruction,
            LookupScope::Regional,
        ));
    }

    /// Looked for an instruction to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_instruction(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Instruction,
            LookupScope::Regional,
        ));
    }

    /// Looking for  an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
            LookupScope::Regional,
        ));
    }

    /// Looked for an ALU operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_alu(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: Word<impl Into<Self::Expr>>,
        b: Word<impl Into<Self::Expr>>,
        c: Word<impl Into<Self::Expr>>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let values = once(opcode.into())
            .chain(a.0.into_iter().map(Into::into))
            .chain(b.0.into_iter().map(Into::into))
            .chain(c.0.into_iter().map(Into::into))
            .collect();

        self.looked(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Alu,
            LookupScope::Regional,
        ));
    }

    /// Sends a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking_byte_pair(opcode, a, Self::Expr::ZERO, b, c, multiplicity);
    }

    /// Sends a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looking_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            LookupType::Byte,
            LookupScope::Regional,
        ));
    }

    /// Sends a new range lookup
    fn looking_rangecheck(
        &mut self,
        opcode: ByteOpcode,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        let opcode = Self::Expr::from_canonical_u8(opcode as u8);
        self.looking_byte_pair(opcode, a1, a2, b, c, multiplicity);
    }

    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked_byte_pair(opcode, a, Self::Expr::ZERO, b, c, multiplicity);
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte_pair(
        &mut self,
        opcode: impl Into<Self::Expr>,
        a1: impl Into<Self::Expr>,
        a2: impl Into<Self::Expr>,
        b: impl Into<Self::Expr>,
        c: impl Into<Self::Expr>,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![opcode.into(), a1.into(), a2.into(), b.into(), c.into()],
            multiplicity.into(),
            LookupType::Byte,
            LookupScope::Regional,
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn looking_syscall(
        &mut self,
        clk: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![
                clk.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
            LookupScope::Regional,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn looked_syscall(
        &mut self,
        clk: impl Into<Self::Expr> + Clone,
        syscall_id: impl Into<Self::Expr> + Clone,
        arg1: impl Into<Self::Expr> + Clone,
        arg2: impl Into<Self::Expr> + Clone,
        multiplicity: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![
                clk.clone().into(),
                syscall_id.clone().into(),
                arg1.clone().into(),
                arg2.clone().into(),
            ],
            multiplicity.into(),
            LookupType::Syscall,
            LookupScope::Regional,
        ))
    }
}
