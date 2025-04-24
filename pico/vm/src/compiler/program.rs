use crate::machine::septic::SepticDigest;

/// A program that defines the control flow of a machine through a program counter.
pub trait ProgramBehavior<F>: Default + Send + Sync {
    /// Gets the starting program counter.
    fn pc_start(&self) -> F;

    fn clone(&self) -> Self;

    fn initial_global_cumulative_sum(&self) -> SepticDigest<F>;
}
