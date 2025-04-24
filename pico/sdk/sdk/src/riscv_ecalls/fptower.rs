#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Fp addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_addmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP_ADD,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_submod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP_SUB,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp_mulmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP_MUL,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BLS12-381 Fp2 addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_addmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP2_ADD,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BLS12-381 Fp2 subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_submod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP2_SUB,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BLS12-381 Fp2 multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bls12381_fp2_mulmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BLS12381_FP2_MUL,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp_addmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP_ADD,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp_submod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP_SUB,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp_mulmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP_MUL,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BN254 Fp2 addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp2_addmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP2_ADD,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BN254 Fp2 subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp2_submod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP2_SUB,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// BN254 Fp2 multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_bn254_fp2_mulmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::BN254_FP2_MUL,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp addition operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_fp_addmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::SECP256K1_FP_ADD,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp subtraction operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_fp_submod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::SECP256K1_FP_SUB,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}

/// Fp multiplication operation.
///
/// The result is written over the first input.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_secp256k1_fp_mulmod(x: *mut u32, y: *const u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "ecall",
            in("t0") crate::riscv_ecalls::SECP256K1_FP_MUL,
            in("a0") x,
            in("a1") y,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
