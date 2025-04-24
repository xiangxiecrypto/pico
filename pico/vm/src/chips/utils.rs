use crate::primitives::consts::{BYTE_SIZE, WORD_SIZE};
use p3_field::Field;
use std::{
    fmt::Display,
    iter::{Map, Peekable},
};

pub const fn indices_arr<const N: usize>() -> [usize; N] {
    let mut indices_arr = [0; N];
    let mut i = 0;
    while i < N {
        indices_arr[i] = i;
        i += 1;
    }
    indices_arr
}

pub const fn get_msb(a: [u8; WORD_SIZE]) -> u8 {
    (a[WORD_SIZE - 1] >> (BYTE_SIZE - 1)) & 1
}

/// Returns sorted and formatted rows of a table of counts (e.g. `opcode_counts`).
///
/// The table is sorted first by count (descending) and then by label (ascending).
/// The first column consists of the counts, is right-justified, and is padded precisely
/// enough to fit all the numbers. The second column consists of the labels (e.g. `OpCode`s).
/// The columns are separated by a single space character.
#[allow(clippy::type_complexity)]
pub fn sorted_table_lines<'a, K, V>(
    table: impl IntoIterator<Item = (K, V)> + 'a,
) -> Map<
    Peekable<Map<std::vec::IntoIter<(K, V)>, impl FnMut((K, V)) -> (String, String)>>,
    impl FnMut((String, String)) -> String,
>
where
    K: Ord + Display + 'a,
    V: Ord + Display + 'a,
{
    let mut entries = table.into_iter().collect::<Vec<_>>();
    // Sort table by count (descending), then the name order (ascending).
    entries.sort_unstable_by(|a, b| a.1.cmp(&b.1).reverse().then_with(|| a.0.cmp(&b.0)));
    // Convert counts to `String`s to prepare them for printing and to measure their width.
    let mut table_with_string_counts = entries
        .into_iter()
        .map(|(label, ct)| (label.to_string().to_lowercase(), ct.to_string()))
        .peekable();
    // Calculate width for padding the counts.
    let width = table_with_string_counts
        .peek()
        .map(|(_, b)| b.len())
        .unwrap_or_default();
    table_with_string_counts.map(move |(label, count)| format!("{count:>width$} {label}"))
}

/// Returns a vector of zeros of the given length. This is faster than vec![F::ZERO; len] which
/// requires copying.
///
/// This function is safe to use only for fields that can be transmuted from 0u32.
pub fn zeroed_f_vec<F: Field>(len: usize) -> Vec<F> {
    debug_assert!(std::mem::size_of::<F>() == 4);

    let vec = vec![0u32; len];
    unsafe { std::mem::transmute::<Vec<u32>, Vec<F>>(vec) }
}

// padding functionalities
pub fn pad_rows_fixed<R: Clone>(
    rows: &mut Vec<R>,
    row_fn: impl Fn() -> R,
    size_log2: Option<usize>,
) {
    let nb_rows = rows.len();
    let dummy_row = row_fn();
    rows.resize(next_power_of_two(nb_rows, size_log2), dummy_row);
}

// padding functionalities
pub fn next_power_of_two(n: usize, fixed_power: Option<usize>) -> usize {
    match fixed_power {
        Some(power) => {
            let padded_nb_rows = 1 << power;
            if n * 2 < padded_nb_rows {
                tracing::warn!(
                    "fixed log2 rows can be potentially reduced: got {}, expected {}",
                    n,
                    padded_nb_rows
                );
            }
            if n > padded_nb_rows {
                panic!(
                    "fixed log2 rows is too small: got {}, expected {}",
                    n, padded_nb_rows
                );
            }
            padded_nb_rows
        }
        None => {
            let mut padded_nb_rows = n.next_power_of_two();
            if padded_nb_rows < 16 {
                padded_nb_rows = 16;
            }
            padded_nb_rows
        }
    }
}
