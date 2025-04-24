#![allow(non_camel_case_types)]
#![allow(clippy::empty_line_after_doc_comments)]

pub mod embed_bb_bn254_poseidon2;
pub mod embed_kb_bn254_poseidon2;
pub mod recur_bb_poseidon2;
pub mod recur_kb_poseidon2;
pub mod riscv_bb_poseidon2;
pub mod riscv_kb_poseidon2;
pub mod riscv_m31_poseidon2;

// replace the following to change global configurations
pub use embed_bb_bn254_poseidon2 as embed_config;
pub use embed_kb_bn254_poseidon2 as embed_kb_config;
pub use recur_bb_poseidon2 as recur_config;
pub use recur_kb_poseidon2 as recur_kb_config;
pub use riscv_bb_poseidon2 as riscv_config;
pub use riscv_kb_poseidon2 as riscv_kb_config;
pub use riscv_m31_poseidon2 as riscv_m31_config;
