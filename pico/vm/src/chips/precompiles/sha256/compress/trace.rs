use std::borrow::BorrowMut;

use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, SHA_COMPRESS_K,
};
use crate::{
    chips::{chips::byte::event::ByteRecordBehavior, utils::pad_rows_fixed},
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{PrecompileEvent, ShaCompressEvent},
            SyscallCode,
        },
    },
    machine::chip::ChipBehavior,
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};

impl<F: PrimeField32> BaseAir<F> for ShaCompressChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaCompressChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "ShaCompress".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = Vec::new();

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_COMPRESS) {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_rows(event, &mut wrapped_rows, &mut Vec::new());
        }
        let mut rows = wrapped_rows.unwrap();
        let num_real_rows = rows.len();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SHA_COMPRESS_COLS], log_rows);

        // Set the octet_num and octect columns for the padded rows.
        let mut octet_num = 0;
        let mut octet = 0;
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.octet_num[octet_num] = F::ONE;
            cols.octet[octet] = F::ONE;

            // If in[ the compression phase, set the k value.
            if octet_num != 0 && octet_num != 9 {
                let compression_idx = octet_num - 1;
                let k_idx = compression_idx * 8 + octet;
                cols.k = Word::from(SHA_COMPRESS_K[k_idx]);
            }

            octet = (octet + 1) % 8;
            if octet == 0 {
                octet_num = (octet_num + 1) % 10;
            }

            cols.is_last_row = cols.octet[7] * cols.octet_num[9];
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let compress_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_COMPRESS)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaCompress(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(compress_events.len() / num_cpus::get(), 1);
        let blu_batches = compress_events
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
                .get_precompile_events(SyscallCode::SHA_COMPRESS)
                .is_empty()
        }
    }
}

impl<F: PrimeField32> ShaCompressChip<F> {
    fn event_to_rows(
        &self,
        event: &ShaCompressEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_COMPRESS_COLS]>>,
        brb: &mut impl ByteRecordBehavior,
    ) {
        let og_h = event.h;

        let mut octet_num_idx = 0;

        // Load a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);

            cols.octet[j] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;
            cols.is_initialize = F::ONE;

            cols.mem.populate_read(event.h_read_records[j], brb);
            cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

            cols.a = Word::from(event.h_read_records[0].value);
            cols.b = Word::from(event.h_read_records[1].value);
            cols.c = Word::from(event.h_read_records[2].value);
            cols.d = Word::from(event.h_read_records[3].value);
            cols.e = Word::from(event.h_read_records[4].value);
            cols.f = Word::from(event.h_read_records[5].value);
            cols.g = Word::from(event.h_read_records[6].value);
            cols.h = Word::from(event.h_read_records[7].value);

            cols.is_real = F::ONE;
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];
            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        // Performs the compress operation.
        let mut h_array = event.h;
        for j in 0..64 {
            if j % 8 == 0 {
                octet_num_idx += 1;
            }
            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.k = Word::from(SHA_COMPRESS_K[j]);
            cols.is_compression = F::ONE;
            cols.octet[j % 8] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;

            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);
            cols.mem.populate_read(event.w_i_read_records[j], brb);
            cols.mem_addr = F::from_canonical_u32(event.w_ptr + (j * 4) as u32);

            let a = h_array[0];
            let b = h_array[1];
            let c = h_array[2];
            let d = h_array[3];
            let e = h_array[4];
            let f = h_array[5];
            let g = h_array[6];
            let h = h_array[7];
            cols.a = Word::from(a);
            cols.b = Word::from(b);
            cols.c = Word::from(c);
            cols.d = Word::from(d);
            cols.e = Word::from(e);
            cols.f = Word::from(f);
            cols.g = Word::from(g);
            cols.h = Word::from(h);

            let e_rr_6 = cols.e_rr_6.populate(brb, e, 6);
            let e_rr_11 = cols.e_rr_11.populate(brb, e, 11);
            let e_rr_25 = cols.e_rr_25.populate(brb, e, 25);
            let s1_intermediate = cols.s1_intermediate.populate(brb, e_rr_6, e_rr_11);
            let s1 = cols.s1.populate(brb, s1_intermediate, e_rr_25);

            let e_and_f = cols.e_and_f.populate(brb, e, f);
            let e_not = cols.e_not.populate(brb, e);
            let e_not_and_g = cols.e_not_and_g.populate(brb, e_not, g);
            let ch = cols.ch.populate(brb, e_and_f, e_not_and_g);

            let temp1 = cols
                .temp1
                .populate(brb, h, s1, ch, event.w[j], SHA_COMPRESS_K[j]);

            let a_rr_2 = cols.a_rr_2.populate(brb, a, 2);
            let a_rr_13 = cols.a_rr_13.populate(brb, a, 13);
            let a_rr_22 = cols.a_rr_22.populate(brb, a, 22);
            let s0_intermediate = cols.s0_intermediate.populate(brb, a_rr_2, a_rr_13);
            let s0 = cols.s0.populate(brb, s0_intermediate, a_rr_22);

            let a_and_b = cols.a_and_b.populate(brb, a, b);
            let a_and_c = cols.a_and_c.populate(brb, a, c);
            let b_and_c = cols.b_and_c.populate(brb, b, c);
            let maj_intermediate = cols.maj_intermediate.populate(brb, a_and_b, a_and_c);
            let maj = cols.maj.populate(brb, maj_intermediate, b_and_c);

            let temp2 = cols.temp2.populate(brb, s0, maj);

            let d_add_temp1 = cols.d_add_temp1.populate(brb, d, temp1);
            let temp1_add_temp2 = cols.temp1_add_temp2.populate(brb, temp1, temp2);

            h_array[7] = g;
            h_array[6] = f;
            h_array[5] = e;
            h_array[4] = d_add_temp1;
            h_array[3] = c;
            h_array[2] = b;
            h_array[1] = a;
            h_array[0] = temp1_add_temp2;

            cols.is_real = F::ONE;
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        let mut v: [u32; 8] = (0..8)
            .map(|i| h_array[i])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        octet_num_idx += 1;
        // Store a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_canonical_u32(event.chunk);
            cols.clk = F::from_canonical_u32(event.clk);
            cols.w_ptr = F::from_canonical_u32(event.w_ptr);
            cols.h_ptr = F::from_canonical_u32(event.h_ptr);

            cols.octet[j] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;
            cols.is_finalize = F::ONE;

            cols.finalize_add.populate(brb, og_h[j], h_array[j]);
            cols.mem.populate_write(event.h_write_records[j], brb);
            cols.mem_addr = F::from_canonical_u32(event.h_ptr + (j * 4) as u32);

            v[j] = h_array[j];
            cols.a = Word::from(v[0]);
            cols.b = Word::from(v[1]);
            cols.c = Word::from(v[2]);
            cols.d = Word::from(v[3]);
            cols.e = Word::from(v[4]);
            cols.f = Word::from(v[5]);
            cols.g = Word::from(v[6]);
            cols.h = Word::from(v[7]);

            match j {
                0 => cols.finalized_operand = cols.a,
                1 => cols.finalized_operand = cols.b,
                2 => cols.finalized_operand = cols.c,
                3 => cols.finalized_operand = cols.d,
                4 => cols.finalized_operand = cols.e,
                5 => cols.finalized_operand = cols.f,
                6 => cols.finalized_operand = cols.g,
                7 => cols.finalized_operand = cols.h,
                _ => panic!("unsupported j"),
            };

            cols.is_real = F::ONE;
            cols.is_last_row = cols.octet[7] * cols.octet_num[9];
            cols.start = cols.is_real * cols.octet_num[0] * cols.octet[0];

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
