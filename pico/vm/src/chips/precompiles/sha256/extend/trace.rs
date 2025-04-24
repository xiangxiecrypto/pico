use crate::{
    chips::{
        chips::byte::event::ByteRecordBehavior,
        precompiles::sha256::extend::{
            columns::{ShaExtendCols, NUM_SHA_EXTEND_COLS},
            ShaExtendChip,
        },
    },
    compiler::riscv::program::Program,
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{PrecompileEvent, ShaExtendEvent},
            SyscallCode,
        },
    },
    machine::chip::ChipBehavior,
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use std::borrow::BorrowMut;

impl<F: PrimeField32> BaseAir<F> for ShaExtendChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaExtendChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaExtend".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        /*let mut new_byte_lookup_events = Vec::new();
        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_EXTEND).iter() {
            let event = if let PrecompileEvent::ShaExtend(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_rows(
                event,
                &mut wrapped_rows,
                &mut new_byte_lookup_events,
                &mut Vec::new(),
            );
        }*/
        let mut new_byte_lookup_events = Vec::new();
        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_EXTEND).iter() {
            let event = if let PrecompileEvent::ShaExtend(event) = event {
                event
            } else {
                unreachable!()
            };

            self.event_to_rows(event, &mut wrapped_rows, &mut new_byte_lookup_events);
        }

        let mut rows = wrapped_rows.unwrap();
        let nb_rows = rows.len();
        let mut padded_nb_rows = nb_rows.next_power_of_two();
        // ensure 16 rows to align with pre-generated shape
        if padded_nb_rows < 16 {
            padded_nb_rows = 16;
        }
        let log_rows = input.shape_chip_size(&self.name());

        if let Some(log_rows) = log_rows {
            padded_nb_rows = 1 << log_rows;
        }

        for i in nb_rows..padded_nb_rows {
            let mut row = [F::ZERO; NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.populate_flags(i);
            rows.push(row);
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let extend_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_EXTEND)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaExtend(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        let chunk_size = std::cmp::max(extend_events.len() / num_cpus::get(), 1);
        let blu_batches = extend_events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    self.event_to_rows(event, &mut None, &mut blu);
                });
                blu
            })
            .collect();

        output.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::SHA_EXTEND)
                .is_empty()
        }
    }
}

impl<F: PrimeField32> ShaExtendChip<F> {
    fn event_to_rows(
        &self,
        event: &ShaExtendEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_EXTEND_COLS]>>,
        brb: &mut impl ByteRecordBehavior,
    ) {
        for j in 0..48usize {
            let mut row = [F::ZERO; NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.is_real = F::ONE;
            cols.populate_flags(j);
            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);

            cols.w_i_minus_15.populate(event.w_i_minus_15_reads[j], brb);
            cols.w_i_minus_2.populate(event.w_i_minus_2_reads[j], brb);
            cols.w_i_minus_16.populate(event.w_i_minus_16_reads[j], brb);
            cols.w_i_minus_7.populate(event.w_i_minus_7_reads[j], brb);

            // `s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift
            // 3)`.
            let w_i_minus_15 = event.w_i_minus_15_reads[j].value;
            let w_i_minus_15_rr_7 = cols.w_i_minus_15_rr_7.populate(brb, w_i_minus_15, 7);
            let w_i_minus_15_rr_18 = cols.w_i_minus_15_rr_18.populate(brb, w_i_minus_15, 18);
            let w_i_minus_15_rs_3 = cols.w_i_minus_15_rs_3.populate(brb, w_i_minus_15, 3);
            let s0_intermediate =
                cols.s0_intermediate
                    .populate(brb, w_i_minus_15_rr_7, w_i_minus_15_rr_18);
            let s0 = cols.s0.populate(brb, s0_intermediate, w_i_minus_15_rs_3);

            // `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift
            // 10)`.
            let w_i_minus_2 = event.w_i_minus_2_reads[j].value;
            let w_i_minus_2_rr_17 = cols.w_i_minus_2_rr_17.populate(brb, w_i_minus_2, 17);
            let w_i_minus_2_rr_19 = cols.w_i_minus_2_rr_19.populate(brb, w_i_minus_2, 19);
            let w_i_minus_2_rs_10 = cols.w_i_minus_2_rs_10.populate(brb, w_i_minus_2, 10);
            let s1_intermediate =
                cols.s1_intermediate
                    .populate(brb, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
            let s1 = cols.s1.populate(brb, s1_intermediate, w_i_minus_2_rs_10);

            // Compute `s2`.
            let w_i_minus_7 = event.w_i_minus_7_reads[j].value;
            let w_i_minus_16 = event.w_i_minus_16_reads[j].value;
            cols.s2.populate(brb, w_i_minus_16, s0, w_i_minus_7, s1);

            cols.w_i.populate(event.w_i_writes[j], brb);

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
