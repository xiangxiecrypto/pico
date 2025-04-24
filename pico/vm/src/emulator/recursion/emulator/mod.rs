mod memory;
mod opcode;

use std::{
    array,
    borrow::Borrow,
    collections::VecDeque,
    fmt::Debug,
    io::{stdout, Write},
    iter::zip,
    marker::PhantomData,
    sync::Arc,
};

use crate::{
    chips::chips::recursion_memory::MemEvent,
    compiler::recursion::{ir::Block, program::RecursionProgram},
    emulator::recursion::emulator::memory::MemVecMap,
    machine::septic::{SepticCurve, SepticExtension},
};
use backtrace::Backtrace as Trace;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField32};
use p3_poseidon2::{ExternalLayer, InternalLayer, Poseidon2};
use p3_symmetric::Permutation;
use p3_util::reverse_bits_len;

use crate::compiler::recursion::types::{
    BaseAluEvent, BaseAluInstr, BatchFRIBaseVecIo, BatchFRIEvent, BatchFRIExtSingleIo,
    BatchFRIExtVecIo, BatchFRIInstr, CommitPublicValuesEvent, ExpReverseBitsEvent,
    ExpReverseBitsInstr, ExpReverseBitsIo, ExtAluEvent, ExtAluInstr, MemAccessKind, MemInstr,
    MemIo, Poseidon2Event, Poseidon2Instr, Poseidon2Io, SelectEvent, SelectInstr, SelectIo,
};
use thiserror::Error;

pub use crate::emulator::recursion::record::*;
use crate::{
    compiler::recursion::instruction::{
        FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        PrintInstr,
    },
    primitives::consts::{PERMUTATION_WIDTH, RECURSION_NUM_PVS},
};
use memory::*;
pub use opcode::*;

#[derive(Debug, Clone, Default)]
pub struct CycleTrackerEntry {
    pub span_entered: bool,
    pub span_enter_cycle: usize,
    pub cumulative_cycles: usize,
}

pub struct Runtime<'a, F, EF, ExternalPerm, InternalPerm, const D: u64>
where
    F: PrimeField32 + Field,
    EF: ExtensionField<F>,
    ExternalPerm: ExternalLayer<F, PERMUTATION_WIDTH, D>,
    InternalPerm: InternalLayer<F, PERMUTATION_WIDTH, D>,
{
    pub timestamp: usize,

    pub nb_poseidons: usize,

    pub nb_wide_poseidons: usize,

    pub nb_bit_decompositions: usize,

    pub nb_ext_ops: usize,

    pub nb_base_ops: usize,

    pub nb_memory_ops: usize,

    pub nb_branch_ops: usize,

    pub nb_select: usize,

    pub nb_exp_reverse_bits: usize,

    pub nb_batch_fri: usize,

    pub nb_print_f: usize,

    pub nb_print_e: usize,

    /// The current clock.
    pub clk: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: Arc<RecursionProgram<F>>,

    /// Memory. From canonical usize of an Address to a MemoryEntry.
    pub memory: MemVecMap<F>,

    /// The emulation record.
    pub record: RecursionRecord<F>,

    pub witness_stream: VecDeque<Block<F>>,

    pub cycle_tracker: HashMap<String, CycleTrackerEntry>,

    /// The stream that print statements write to.
    pub debug_stdout: Box<dyn Write + 'a>,

    /// Entries for dealing with the Poseidon2 hash state.
    perm:
        Option<Poseidon2<<F as Field>::Packing, ExternalPerm, InternalPerm, PERMUTATION_WIDTH, D>>,

    _marker_ef: PhantomData<EF>,
}

#[derive(Error, Debug)]
pub enum RuntimeError<F: Debug, EF: Debug> {
    #[error(
        "attempted to perform base field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivFOutOfDomain {
        in1: F,
        in2: F,
        instr: BaseAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error(
        "attempted to perform extension field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivEOutOfDomain {
        in1: EF,
        in2: EF,
        instr: ExtAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error("failed to print to `debug_stdout`: {0}")]
    DebugPrint(#[from] std::io::Error),
    #[error("attempted to read from empty witness stream")]
    EmptyWitnessStream,
}

impl<F, EF, ExternalPerm, InternalPerm, const D: u64>
    Runtime<'_, F, EF, ExternalPerm, InternalPerm, D>
where
    F: PrimeField32 + Field,
    EF: ExtensionField<F>,
    ExternalPerm: ExternalLayer<F, PERMUTATION_WIDTH, D>,
    InternalPerm: InternalLayer<F, PERMUTATION_WIDTH, D>,
{
    pub fn new(
        program: Arc<RecursionProgram<F>>,
        perm: Poseidon2<<F as Field>::Packing, ExternalPerm, InternalPerm, PERMUTATION_WIDTH, D>,
    ) -> Self {
        let record = RecursionRecord::<F> {
            program: program.clone(),
            ..Default::default()
        };
        let memory = Memory::with_capacity(program.total_memory);
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_wide_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_select: 0,
            nb_exp_reverse_bits: 0,
            nb_batch_fri: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            clk: F::ZERO,
            program,
            pc: F::ZERO,
            memory,
            record,
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            debug_stdout: Box::new(stdout()),
            perm: Some(perm),
            _marker_ef: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        // print all stats
        tracing::info!("   |- {:<26}: {}", "Total Cycles:", self.timestamp);
        tracing::info!(
            "   |- {:<26}: {}",
            "Poseidon Operations:",
            self.nb_poseidons
        );
        tracing::info!(
            "   |- {:<26}: {}",
            "Exp Reverse Bits Operations:",
            self.nb_exp_reverse_bits
        );
        tracing::info!(
            "   |- {:<26}: {}",
            "BatchFRI Operations:",
            self.nb_batch_fri
        );
        tracing::info!("   |- {:<26}: {}", "Field Operations:", self.nb_base_ops);
        tracing::info!("   |- {:<26}: {}", "Extension Operations:", self.nb_ext_ops);
        tracing::info!("   |- {:<26}: {}", "Memory Operations:", self.nb_memory_ops);
        tracing::info!("   |- {:<26}: {}", "Branch Operations:", self.nb_branch_ops);

        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            tracing::info!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    fn nearest_pc_backtrace(&mut self) -> Option<(usize, Trace)> {
        let trap_pc = self.pc.as_canonical_u32() as usize;
        let trace = self.program.traces.get(trap_pc).cloned()?;
        if let Some(mut trace) = trace {
            trace.resolve();
            Some((trap_pc, trace))
        } else {
            (0..trap_pc)
                .rev()
                .filter_map(|nearby_pc| {
                    let mut trace = self.program.traces.get(nearby_pc)?.clone()?;
                    trace.resolve();
                    Some((nearby_pc, trace))
                })
                .next()
        }
    }

    pub fn run(&mut self) -> Result<(), RuntimeError<F, EF>> {
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        while self.pc < F::from_canonical_u32(self.program.instructions.len() as u32) {
            let idx = self.pc.as_canonical_u32() as usize;
            let instruction = self.program.instructions[idx].clone();

            let next_clk = self.clk + F::from_canonical_u32(4);
            let next_pc = self.pc + F::ONE;
            match instruction {
                Instruction::BaseAlu(
                    instr @ BaseAluInstr {
                        opcode,
                        mult,
                        addrs,
                    },
                ) => {
                    self.nb_base_ops += 1;
                    let in1 = self.memory.mr(addrs.in1).val[0];
                    let in2 = self.memory.mr(addrs.in2).val[0];
                    // Do the computation.
                    let out = match opcode {
                        BaseAluOpcode::AddF => in1 + in2,
                        BaseAluOpcode::SubF => in1 - in2,
                        BaseAluOpcode::MulF => in1 * in2,
                        BaseAluOpcode::DivF => match in2.try_inverse() {
                            Some(x) => in1 * x,
                            None => {
                                // Check for division exceptions and error. Note that 0/0 is defined
                                // to be 1.
                                if in1.is_zero() {
                                    FieldAlgebra::ONE
                                } else {
                                    return Err(RuntimeError::DivFOutOfDomain {
                                        in1,
                                        in2,
                                        instr,
                                        pc: self.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace(),
                                    });
                                }
                            }
                        },
                    };
                    self.memory.mw(addrs.out, Block::from(out), mult);
                    self.record
                        .base_alu_events
                        .push(BaseAluEvent { out, in1, in2 });
                }
                Instruction::ExtAlu(
                    instr @ ExtAluInstr {
                        opcode,
                        mult,
                        addrs,
                    },
                ) => {
                    self.nb_ext_ops += 1;
                    let in1 = self.memory.mr(addrs.in1).val;
                    let in2 = self.memory.mr(addrs.in2).val;
                    // Do the computation.
                    let in1_ef = EF::from_base_slice(&in1.0);
                    let in2_ef = EF::from_base_slice(&in2.0);
                    let out_ef = match opcode {
                        ExtAluOpcode::AddE => in1_ef + in2_ef,
                        ExtAluOpcode::SubE => in1_ef - in2_ef,
                        ExtAluOpcode::MulE => in1_ef * in2_ef,
                        ExtAluOpcode::DivE => match in2_ef.try_inverse() {
                            Some(x) => in1_ef * x,
                            None => {
                                // Check for division exceptions and error. Note that 0/0 is defined
                                // to be 1.
                                if in1_ef.is_zero() {
                                    FieldAlgebra::ONE
                                } else {
                                    return Err(RuntimeError::DivEOutOfDomain {
                                        in1: in1_ef,
                                        in2: in2_ef,
                                        instr,
                                        pc: self.pc.as_canonical_u32() as usize,
                                        trace: self.nearest_pc_backtrace(),
                                    });
                                }
                            }
                        },
                    };
                    let out = Block::from(out_ef.as_base_slice());
                    self.memory.mw(addrs.out, out, mult);
                    self.record
                        .ext_alu_events
                        .push(ExtAluEvent { out, in1, in2 });
                }
                Instruction::Mem(MemInstr {
                    addrs: MemIo { inner: addr },
                    vals: MemIo { inner: val },
                    mult,
                    kind,
                }) => {
                    self.nb_memory_ops += 1;
                    match kind {
                        MemAccessKind::Read => {
                            let mem_entry = self.memory.mr_mult(addr, mult);
                            assert_eq!(
                                mem_entry.val, val,
                                "stored memory value should be the specified value"
                            );
                        }
                        MemAccessKind::Write => drop(self.memory.mw(addr, val, mult)),
                    }
                    self.record.mem_const_count += 1;
                }
                Instruction::Poseidon2(instr) => {
                    let Poseidon2Instr {
                        addrs: Poseidon2Io { input, output },
                        mults,
                    } = *instr;
                    self.nb_poseidons += 1;
                    let in_vals = std::array::from_fn(|i| self.memory.mr(input[i]).val[0]);
                    let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                    perm_output
                        .iter()
                        .zip(output)
                        .zip(mults)
                        .for_each(|((&val, addr), mult)| {
                            self.memory.mw(addr, Block::from(val), mult);
                        });
                    self.record.poseidon2_events.push(Poseidon2Event {
                        input: in_vals,
                        output: perm_output,
                    });
                }
                Instruction::Select(SelectInstr {
                    addrs:
                        SelectIo {
                            bit,
                            out1,
                            out2,
                            in1,
                            in2,
                        },
                    mult1,
                    mult2,
                }) => {
                    self.nb_select += 1;
                    let bit = self.memory.mr(bit).val[0];
                    let in1 = self.memory.mr(in1).val[0];
                    let in2 = self.memory.mr(in2).val[0];
                    let out1_val = bit * in2 + (F::ONE - bit) * in1;
                    let out2_val = bit * in1 + (F::ONE - bit) * in2;
                    self.memory.mw(out1, Block::from(out1_val), mult1);
                    self.memory.mw(out2, Block::from(out2_val), mult2);
                    self.record.select_events.push(SelectEvent {
                        bit,
                        out1: out1_val,
                        out2: out2_val,
                        in1,
                        in2,
                    })
                }
                Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                    addrs: ExpReverseBitsIo { base, exp, result },
                    mult,
                }) => {
                    self.nb_exp_reverse_bits += 1;
                    let base_val = self.memory.mr(base).val[0];
                    let exp_bits: Vec<_> =
                        exp.iter().map(|bit| self.memory.mr(*bit).val[0]).collect();
                    let exp_val = exp_bits
                        .iter()
                        .enumerate()
                        .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
                    let out =
                        base_val.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
                    self.memory.mw(result, Block::from(out), mult);
                    self.record
                        .exp_reverse_bits_len_events
                        .push(ExpReverseBitsEvent {
                            result: out,
                            base: base_val,
                            exp: exp_bits,
                        });
                }
                Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr,
                }) => {
                    self.nb_bit_decompositions += 1;
                    let num = self.memory.mr_mult(input_addr, F::ZERO).val[0].as_canonical_u32();
                    // Decompose the num into LE bits.
                    let bits = (0..output_addrs_mults.len())
                        .map(|i| Block::from(F::from_canonical_u32((num >> i) & 1)))
                        .collect::<Vec<_>>();
                    // Write the bits to the array at dst.
                    for (bit, (addr, mult)) in bits.into_iter().zip(output_addrs_mults) {
                        self.memory.mw(addr, bit, mult);
                        self.record.mem_var_events.push(MemEvent { inner: bit });
                    }
                }

                Instruction::BatchFRI(instr) => {
                    let BatchFRIInstr {
                        base_vec_addrs,
                        ext_single_addrs,
                        ext_vec_addrs,
                        acc_mult,
                    } = *instr;

                    let mut acc = EF::ZERO;
                    let p_at_xs = base_vec_addrs
                        .p_at_x
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val[0])
                        .collect_vec();
                    let p_at_zs = ext_vec_addrs
                        .p_at_z
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                        .collect_vec();
                    let alpha_pows: Vec<_> = ext_vec_addrs
                        .alpha_pow
                        .iter()
                        .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                        .collect_vec();

                    self.nb_batch_fri += p_at_zs.len();
                    for m in 0..p_at_zs.len() {
                        acc += alpha_pows[m] * (p_at_zs[m] - EF::from_base(p_at_xs[m]));
                        self.record.batch_fri_events.push(BatchFRIEvent {
                            base_vec: BatchFRIBaseVecIo { p_at_x: p_at_xs[m] },
                            ext_single: BatchFRIExtSingleIo {
                                acc: Block::from(acc.as_base_slice()),
                            },
                            ext_vec: BatchFRIExtVecIo {
                                p_at_z: Block::from(p_at_zs[m].as_base_slice()),
                                alpha_pow: Block::from(alpha_pows[m].as_base_slice()),
                            },
                        });
                    }

                    let _ = self.memory.mw(
                        ext_single_addrs.acc,
                        Block::from(acc.as_base_slice()),
                        acc_mult,
                    );
                }

                Instruction::CommitPublicValues(instr) => {
                    let pv_addrs = instr.pv_addrs.as_array();
                    let pv_values: [F; RECURSION_NUM_PVS] =
                        array::from_fn(|i| self.memory.mr(pv_addrs[i]).val[0]);
                    self.record.public_values = *pv_values.as_slice().borrow();
                    self.record
                        .commit_pv_hash_events
                        .push(CommitPublicValuesEvent {
                            public_values: self.record.public_values,
                        });
                }

                Instruction::HintAddCurve(instr) => {
                    let HintAddCurveInstr {
                        output_x_addrs_mults,
                        output_y_addrs_mults,
                        input1_x_addrs,
                        input1_y_addrs,
                        input2_x_addrs,
                        input2_y_addrs,
                    } = *instr;
                    let input1_x = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr_mult(input1_x_addrs[i], F::ZERO).val[0]
                    });
                    let input1_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr_mult(input1_y_addrs[i], F::ZERO).val[0]
                    });
                    let input2_x = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr_mult(input2_x_addrs[i], F::ZERO).val[0]
                    });
                    let input2_y = SepticExtension::<F>::from_base_fn(|i| {
                        self.memory.mr_mult(input2_y_addrs[i], F::ZERO).val[0]
                    });
                    let point1 = SepticCurve {
                        x: input1_x,
                        y: input1_y,
                    };
                    let point2 = SepticCurve {
                        x: input2_x,
                        y: input2_y,
                    };
                    let output = point1.add_incomplete(point2);

                    for (val, (addr, mult)) in
                        output.x.0.into_iter().zip(output_x_addrs_mults.into_iter())
                    {
                        self.memory.mw(addr, Block::from(val), mult);
                        self.record.mem_var_events.push(MemEvent {
                            inner: Block::from(val),
                        });
                    }
                    for (val, (addr, mult)) in
                        output.y.0.into_iter().zip(output_y_addrs_mults.into_iter())
                    {
                        self.memory.mw(addr, Block::from(val), mult);
                        self.record.mem_var_events.push(MemEvent {
                            inner: Block::from(val),
                        });
                    }
                }

                Instruction::Print(PrintInstr {
                    field_elt_type,
                    addr,
                }) => match field_elt_type {
                    FieldEltType::Base => {
                        self.nb_print_f += 1;
                        let f = self.memory.mr_mult(addr, F::ZERO).val[0];
                        writeln!(self.debug_stdout, "PRINTF={f}")
                    }
                    FieldEltType::Extension => {
                        self.nb_print_e += 1;
                        let ef = self.memory.mr_mult(addr, F::ZERO).val;
                        writeln!(self.debug_stdout, "PRINTEF={ef:?}")
                    }
                }
                .map_err(RuntimeError::DebugPrint)?,
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr,
                }) => {
                    self.nb_bit_decompositions += 1;
                    let fs = self.memory.mr_mult(input_addr, F::ZERO).val;
                    // Write the bits to the array at dst.
                    for (f, (addr, mult)) in fs.into_iter().zip(output_addrs_mults) {
                        let felt = Block::from(f);
                        self.memory.mw(addr, felt, mult);
                        self.record.mem_var_events.push(MemEvent { inner: felt });
                    }
                }
                Instruction::Hint(HintInstr { output_addrs_mults }) => {
                    // Check that enough Blocks can be read, so `drain` does not panic.
                    if self.witness_stream.len() < output_addrs_mults.len() {
                        return Err(RuntimeError::EmptyWitnessStream);
                    }
                    let witness = self.witness_stream.drain(0..output_addrs_mults.len());
                    for ((addr, mult), val) in zip(output_addrs_mults, witness) {
                        // Inline [`Self::mw`] to mutably borrow multiple fields of `self`.
                        self.memory.mw(addr, val, mult);
                        self.record.mem_var_events.push(MemEvent { inner: val });
                    }
                }
            }

            self.pc = next_pc;
            self.clk = next_clk;
            self.timestamp += 1;

            if self.timestamp >= early_exit_ts {
                break;
            }
        }
        Ok(())
    }
}
