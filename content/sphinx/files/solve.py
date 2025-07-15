from copy import deepcopy as copy
import secrets
import itertools
from sboxes import SBOXES
from sphinx_deobf import Khafre


mode = "trace"
# mode = "local"
# mode = "remote"

if mode == "trace":
    real_key = secrets.token_bytes(8)
    khafre = Khafre(real_key)

    real_flag = b"testflag"
    orig_encryption = khafre.encrypt(real_flag)

    n_encryptions = 0

    def task_encrypt(pt):
        global n_encryptions
        n_encryptions += 1
        return khafre.encrypt(pt, debug_trace=True)
    
    def task_submit(flag):
        if flag == real_flag:
            print("success")
        else:
            print(f"fail {flag.hex()} != {real_flag.hex()}")
        print(f"in {n_encryptions} encryptions")
        exit()
else:
    from pwn import process, remote, context

    context.encoding = "ASCII"

    if mode == "local":
        pi = process(["python", "sphinx.py"])
    elif mode == "remote":
        pi = remote("sphinx.2025.ctfcompetition.com", 1337)
    else:
        raise ValueError()
    
    if mode == "remote":
        try:
            pi.recvuntil("== proof-of-work: enabled ==", timeout=2)
            pi.recvline()
            pi.recvline()
            pi.recvline()
            print("Solve the POW")
            print(pi.recvline().decode())
            pi.sendline(input())
        except TimeoutError:
            pass

    
    pi.recvuntil("I say you:", timeout=10)
    orig_encryption = bytes.fromhex(pi.recvline().decode().strip())

    n_encryptions = 0

    def task_encrypt(pt):
        global n_encryptions
        n_encryptions += 1
        pi.sendlineafter("You say I:", pt.hex().upper(), timeout=10)
        pi.recvuntil("I say you:", timeout=10)
        return bytes.fromhex(pi.recvline().decode().strip())
    
    def task_submit(flag):
        pi.sendlineafter("You say I:", flag.hex().upper(), timeout=10)
        print(f"after {n_encryptions} encryptions")
        pi.interactive()


def swap(b):
    return b[4:] + b[:4]

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

ROTATION_SCHEDULE = [16, 16, 8, 8, 16, 16, 24, 24]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def generate_encryptions():
    encryptions = []
    p1 = secrets.token_bytes(8)
    for A in range(0, 2 ** 8):
        pt = xor(p1, bytes([0, 0, A, 0, 0, 0, 0, 0]))
        ct = swap(task_encrypt(swap(pt)))
        if mode == "trace":
            tr = khafre.trace
        else:
            tr = None
        encryptions.append((pt, ct, tr))
    return encryptions

LUTS = [None] * len(SBOXES)

def ensure_lut(sbox_index=1):
    if LUTS[sbox_index] is not None:
        return
    sbox = SBOXES[sbox_index]
    LUTS[sbox_index] = {
        (rotr(sbox[i], 16) ^ rotr(sbox[j], 16) ^ sbox[k]): (i, j, k)
        for i, j, k in itertools.product(range(256), repeat=3)
    }

def match_output_xor_xor(x, sbox_index=1):
    ensure_lut(sbox_index=sbox_index)
    sbox = SBOXES[sbox_index]
    lut = LUTS[sbox_index]
    anss = []
    for l in range(256):
        if x ^ sbox[l] in lut:
            i, j, k = lut[x ^ sbox[l]]
            assert rotr(sbox[i], 16) ^ rotr(sbox[j], 16) ^ sbox[k] ^ sbox[l] == x
            if (i, j, k, l) in anss or (i, j, l, k) in anss or (j, i, k, l) in anss or (j, i, l, k) in anss:
                continue
            anss.append((i, j, k, l))
    return anss

class Knowns:
    pass

def print_trace(s):
    if mode != "trace":
        return
    print("--- Trace of first encryption ---")
    print( "  round  |    left     |    right    |  Output XOR")
    left, right = s.pt1[:4], s.pt1[4:]
    print(f"  input  | {left.hex(' ')} | {right.hex(' ')} |")
    for i, t in enumerate(s.tr1):
        left, right, output = (x.to_bytes(4, 'big') for x in t)
        print(f"round {i + 1:02} | {left.hex(' ')} | {right.hex(' ')} | {output.hex(' ')}")
    left, right = s.ct1[:4], s.ct1[4:]
    print(f" output  | {left.hex(' ')} | {right.hex(' ')} |")
    print()
    print("--- Differential trace ---")
    print( "  round  |    left     |    right    |  Output XOR")
    left, right = s.pt_xor[:4], s.pt_xor[4:]
    print(f"  input  | {left.hex(' ')} | {right.hex(' ')} |")
    for i, (t1, t2) in enumerate(zip(s.tr1, s.tr2)):
        left, right, output = ((x ^ y).to_bytes(4, 'big') for x, y in zip(t1, t2))
        print(f"round {i + 1:02} | {left.hex(' ')} | {right.hex(' ')} | {output.hex(' ')}")
    left, right = s.ct_xor[:4], s.ct_xor[4:]
    print(f" output  | {left.hex(' ')} | {right.hex(' ')} |")

def process_pairs(encryptions):
    for (pt1, ct1, tr1), (pt2, ct2, tr2) in itertools.combinations(encryptions, 2):
        s = Knowns()
        s.pt1 = pt1
        s.pt2 = pt2
        s.ct1 = ct1
        s.ct2 = ct2
        s.tr1 = tr1
        s.tr2 = tr2

        s.pt_xor = xor(s.pt1, s.pt2)
        s.ct_xor = xor(s.ct1, s.ct2)

        s.A = s.pt_xor[2]

        xx = int.from_bytes(xor(s.ct_xor[:4], s.pt_xor[:4]), 'big')

        for i, j, k, l in match_output_xor_xor(xx):
            step1(copy(s), i, j, k, l)

def step1(s, i, j, k, l):
    s.r9_indicies = (k, l)
    s.E = k ^ l
    s.F, s.G, HA, s.I = (SBOXES[1][k] ^ SBOXES[1][l]).to_bytes(4, 'big')
    s.H = HA ^ s.A

    s.r11_indicies = (i, j)
    s.M = i ^ j

    s.Q, s.R, s.N, s.P, s.Y, s.Z, s.alpha, s.beta = s.ct_xor

    # look for r8
    for i in range(256):
        j = i ^ s.A
        if i > j:
            continue
        if (SBOXES[0][i] ^ SBOXES[0][j]) & 0xFF == s.E:
            step2(copy(s), i, j)
    
def step2(s, i, j):
    s.r8_indicies = (i, j)
    s.B, s.C, s.D, _ = (SBOXES[0][i] ^ SBOXES[0][j]).to_bytes(4, 'big')

    # look for r10
    MC = s.M ^ s.C
    for i in range(256):
        j = i ^ s.I
        if i > j:
            continue
        if (SBOXES[1][i] ^ SBOXES[1][j]) & 0xFF == MC:
            step3(copy(s), i, j)

def step3(s, i, j):
    s.r10_indicies = (i, j)
    JD, KE, LB, _ = (SBOXES[1][i] ^ SBOXES[1][j]).to_bytes(4, 'big')
    s.J = JD ^ s.D
    s.K = KE ^ s.E
    s.L = LB ^ s.B

    # look for r12
    for i in range(256):
        j = i ^ s.R
        if i > j:
            continue
        if (SBOXES[1][i] ^ SBOXES[1][j]) & 0xFF == s.L:
            step4(copy(s), i, j)

def step4(s, i, j):
    s.r12_indicies = (i, j)
    SM, TJ, UK, _ = (SBOXES[1][i] ^ SBOXES[1][j]).to_bytes(4, 'big')
    s.S = SM ^ s.M
    s.T = TJ ^ s.J
    s.U = UK ^ s.K

    # look for r14
    for i in range(256):
        j = i ^ s.Q
        if i > j:
            continue
        if (SBOXES[1][i] ^ SBOXES[1][j]) & 0xFF == s.T:
            step5(s, i, j)

def step5(s, i, j):
    s.r14_indicies = (i, j)
    VU, s.W, XS, _ = (SBOXES[1][i] ^ SBOXES[1][j]).to_bytes(4, 'big')
    s.V = VU ^ s.U
    s.X = XS ^ s.S

    # look for r16
    for i in range(256):
        j = i ^ s.N
        if i > j:
            continue
        if (SBOXES[1][i] ^ SBOXES[1][j]).to_bytes(4, 'big') == bytes([s.Y ^ s.W, s.Z ^ s.X, s.alpha, s.beta ^ s.V]):
            step6(copy(s), i, j)


def step6(s, i, j):
    s.r16_indicies = (i, j)
    for r16 in s.r16_indicies:
        # byte 2 of the shifted key
        k2 = s.ct1[2] ^ r16
        # shift back to what is xored in round 8
        k2 = (k2 << 1) & 0xFF

        # now we can use r8
        for r8 in s.r8_indicies:
            x = r8 ^ k2
            for r9, r11 in itertools.product(s.r9_indicies, s.r11_indicies):
                step7(copy(s), x, r9, r11, r16)


def step7(s, x, r9, r11, r16):
    x ^= (SBOXES[1][r9] >> 8) & 0xFF
    x ^= (SBOXES[1][r11] >> 24) & 0xFF
    # x ^= (SBOXES[1][r13] >> 16) & 0xFF
    # x ^= SBOXES[1][r15] & 0xFF
    # x == r16 except for the first bit

    # find r13 and r15
    for r13 in range(256):
        for r15 in range(256):
            y = x ^ ((SBOXES[1][r13] >> 16) & 0xFF) ^ (SBOXES[1][r15] & 0xFF)
            if (y & 0xFE) == (r16 & 0xFE):
                for r10, r12, r14 in itertools.product(s.r10_indicies, s.r12_indicies, s.r14_indicies):
                    step8(copy(s), (r9, r10, r11, r12, r13, r14, r15, r16))

def step8(s, indicies):
    left, right = bytearray([0] * 4), bytearray([0] * 4)
        
    for i, x in enumerate(indicies):
        right[-1] = x
        left, right = rotr(int.from_bytes(right, 'big'), ROTATION_SCHEDULE[i]).to_bytes(4, 'big'), xor(left, SBOXES[1][x].to_bytes(4, 'big'))
        left, right = bytearray(left), bytearray(right)

    left, right = xor(left, s.ct1[:4]), xor(right, s.ct1[4:])

    def rotl_bytes(b, n):
        return rotl(int.from_bytes(b, 'big'), n).to_bytes(4, 'big')

    left, right = rotl_bytes(left, 2), rotl_bytes(right, 2)
    
    key = left + right
    
    cc = Khafre(swap(key))

    if swap(cc.encrypt(swap(s.pt1))) != s.ct1:
        return
    if swap(cc.encrypt(swap(s.pt2))) != s.ct2:
        return

    flag = cc.decrypt(orig_encryption)

    print_trace(s)
    
    task_submit(flag)


if __name__ == "__main__":
    while True:
        encryptions = generate_encryptions()
        process_pairs(encryptions)

