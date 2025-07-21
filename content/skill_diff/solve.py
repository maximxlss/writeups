from sage.all import *
import hashlib
from random import randbytes


KEY = b"some1fixed2key34"

sb = (238, 180, 132, 65, 223, 139, 245, 252, 68, 184, 227, 73, 30, 225, 253, 204, 86, 7, 202, 243, 41, 213, 118, 167, 136, 193, 236, 107, 33, 13, 183, 229, 105, 55, 182, 94, 155, 109, 18, 119, 186, 52, 224, 221, 131, 83, 165, 110, 113, 185, 44, 209, 228, 157, 148, 143, 108, 134, 101, 141, 80, 31, 40, 23, 210, 154, 244, 181, 22, 226, 97, 151, 251, 76, 102, 125, 45, 158, 240, 137, 25, 235, 248, 53, 153, 166, 164, 208, 220, 198, 106, 88, 201, 163, 38, 121, 10, 82, 84, 173, 215, 161, 63, 24, 250, 57, 66, 4, 21, 1, 5, 43, 27, 92, 58, 218, 112, 114, 171, 103, 177, 99, 50, 87, 211, 122, 0, 39, 138, 75, 46, 239, 2, 6, 91, 176, 178, 127, 237, 169, 133, 34, 231, 15, 11, 81, 49, 69, 62, 123, 212, 71, 90, 249, 172, 98, 233, 254, 255, 203, 116, 8, 128, 200, 74, 145, 205, 187, 222, 59, 70, 16, 26, 207, 160, 217, 191, 246, 179, 72, 150, 140, 89, 14, 64, 174, 37, 232, 242, 170, 19, 47, 216, 77, 9, 67, 104, 36, 135, 35, 147, 60, 247, 117, 129, 56, 175, 196, 189, 149, 206, 42, 152, 192, 120, 51, 96, 85, 93, 144, 146, 126, 100, 48, 29, 32, 194, 130, 197, 162, 188, 61, 142, 95, 3, 159, 28, 124, 241, 190, 219, 230, 156, 20, 214, 54, 199, 111, 168, 79, 234, 195, 17, 12, 115, 78)  # fmt: skip

inv_sbox = [0] * 256

for i, c in enumerate(sb):
    inv_sbox[c] = i

M = Matrix(
    Zmod(256),
    [
        (0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0),
        (0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 0, 0),
        (0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0),
        (0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0),
        (0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0),
        (1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0),
        (0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0),
        (0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0),
        (1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1),
        (0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0),
        (0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1),
        (0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0),
        (1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0),
        (1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1),
        (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
    ],
)

inv_M = M.inverse()

aff = [[109, 211], [123, 254], [81, 20], [129, 182], [251, 74], [57, 11], [213, 44], [155, 52], [205, 146], [239, 12], [123, 218], [143, 178], [63, 228], [153, 223], [237, 1], [133, 72]]  # fmt: skip

inv_aff = [[inverse_mod(a, 256), -inverse_mod(a, 256) * b] for a, b in aff]


def f(i, x):
    a, b = aff[i]
    x = (a * x + b) % 256
    x = int(x) ^ 1
    x = sb[x]
    return x


def inv_f(i, x):
    x = inv_sbox[x]
    x = int(x) ^ 1
    a, b = inv_aff[i]
    x = (a * x + b) % 256
    return x


def generate_round_keys(master):
    res = [master]
    for i in range(3):
        h = hashlib.sha256()
        h.update(bytes(res[-1]))
        h.update(bytes(master))
        res.append(list(h.digest()[:16]))
    return res


ROUND_KEYS = generate_round_keys(KEY)

def encrypt_block(block, key=None):
    if key is not None:
        round_keys = generate_round_keys(key)
    else:
        round_keys = ROUND_KEYS
    block = [(b + k) % 256 for b, k in zip(block, round_keys[0])]
    for r in range(3):
        block = list(map(Integer, M * vector(block)))
        for i in range(16):
            block[i] = f(i, block[i])
            block[i] = (block[i] + round_keys[r + 1][i]) % 256
    return block


def decrypt_block(block, key=None):
    if key is not None:
        round_keys = generate_round_keys(key)
    else:
        round_keys = ROUND_KEYS
    for r in range(2, -1, -1):
        for i in range(16):
            block[i] = (block[i] - round_keys[r + 1][i]) % 256
            block[i] = inv_f(i, block[i])
        block = list(map(Integer, inv_M * vector(block)))
    block = [(b - k) % 256 for b, k in zip(block, round_keys[0])]
    return block


def diff_at(i, x):
    diff = [0] * 16
    diff[i] = x
    return vector(diff)


def gen_pts(base, i):
    pts = []
    for x in range(256):
        diff = inv_M * diff_at(i, x)
        pts.append(base + diff)
    return pts


def encpts(pts, key=None):
    return [(pt, encrypt_block(pt, key)) for pt in pts]


Mz = M.change_ring(ZZ)


def get_ct_diff(v1_diff):
    v1 = M * v1_diff
    v1 = vector(ZZ, [x != 0 for x in v1])
    v2 = Mz * v1
    return tuple(x != 0 for x in v2)


def get_char(i, j):
    v1 = get_ct_diff(diff_at(i, 1) + diff_at(j, 1))
    v2 = get_ct_diff(diff_at(i, 1) + diff_at(j, 255))
    diff = tuple(x - y for x, y in zip(v1, v2))
    assert all(x == 0 or x == 1 for x in diff)
    return tuple(i for i in range(16) if diff[i])


def gather_pairs(i, j):
    res = set()

    char = get_char(i, j)
    prs1 = pairs_collections[i]
    prs2 = pairs_collections[j]

    for pt1, ct1 in prs1:
        for pt2, ct2 in prs2:
            ctdiff = [x != y for x, y in zip(ct1, ct2)]
            if all(not ctdiff[i] for i in char):
                m_pt1 = M * vector(pt1)
                x1i = m_pt1[i]
                x1j = m_pt1[j]
                m_pt2 = M * vector(pt2)
                m_v0 = m_pt2 - m_pt1
                dxi, dxj = m_v0[i], m_v0[j]

                res.add((dxi, dxj, x1i, x1j))

    return res


k_recovered = [None] * 16


def find_char(i):
    js = []
    for jj in range(16):
        if i == jj:
            continue
        char = get_char(i, jj)
        if len(char) >= 2:
            js.append(jj)
    best_js = [j for j in js if k_recovered[j] is None]
    if best_js:
        return best_js[0]
    elif js:
        return js[0]
    else:
        return None


def diffs_lut(i):
    lut = {}
    for dx in range(256):
        if dx not in lut:
            lut[dx] = {}
        for x in range(256):
            lut[dx][(f(i, (x + dx) % 256) - f(i, x)) % 256] = x
    return lut

luts = [diffs_lut(i) for i in range(16)]


def find_k_byte(i):
    j = find_char(i)
    if j is None:
        return None

    lut = luts[j]

    res = gather_pairs(i, j)

    sol = {}
    for dxi, dxj, x1i, x1j in res:
        pairs = set()
        for k0 in range(256):
            x = (f(i, x1i + k0) - f(i, x1i + k0 + dxi)) % 256
            if x in lut[dxj]:
                k1 = lut[dxj][x] - x1j
                pairs.add((k0, k1))
        for pair in pairs:
            sol[pair] = sol.get(pair, 0) + 1

    right_pairs = [pair for pair, v in sol.items() if v > 50]
    assert len(right_pairs) == 1, right_pairs
    right_pair = right_pairs[0]

    if k_recovered[i] is not None:
        assert k_recovered[i] == right_pair[0]
    else:
        k_recovered[i] = right_pair[0]
    if k_recovered[j] is not None:
        assert k_recovered[j] == right_pair[1]
    else:
        k_recovered[j] = right_pair[1]


def ensure_k_recovered():
    for i in range(16):
        if k_recovered[i] is not None:
            continue
        find_k_byte(i)
        print(k_recovered)


def get_key_candidates():
    keys = []
    idx = [i for i in range(16) if k_recovered[i] is None]
    assert len(idx) == 1
    i = idx[0]
    for x in range(256):
        k_candidate = k_recovered.copy()
        k_candidate[i] = x
        key = inv_M * vector(k_candidate)
        key = list(key)
        keys.append(key)
    return keys


def get_key():
    ensure_k_recovered()
    pt, ct = pairs_collections[0][0]
    valid = []
    for key in get_key_candidates():
        if encrypt_block(pt, key=key) == ct:
            valid.append(key)
    assert len(valid) == 1
    return valid[0]


print("preparation done")

base = vector(randbytes(16))

pts_collections = [gen_pts(base, i) for i in range(16)]
# with open("input.enc", "wb") as ff:
#     for pts in pts_col:
#         for pt in pts:
#             ff.write(bytes(pt))

# input("enc the file now > ")

# with open("input.enc", "rb") as ff:
#     prs_col = []
#     for pts in pts_col:
#         prs = []
#         for pt in pts:
#             ct = list(ff.read(16))
#             prs.append((pt, ct))
#         prs_col.append(prs)
#     assert ff.read() == b""

pairs_collections = [encpts(pts) for pts in pts_collections]

print("enc done")

key = get_key()


# def decrypt_ecb(ciphertext, key):
#     # Check that the ciphertext length is a multiple of the block size
#     if len(ciphertext) % 16 != 0:
#         raise ValueError("Ciphertext length must be a multiple of 16 bytes")

#     plaintext = bytearray()

#     # Process each 16-byte block independently
#     for i in range(0, len(ciphertext), 16):
#         block = list(ciphertext[i : i + 16])
#         decrypted_block = decrypt_block(block, key=key)
#         plaintext.extend(decrypted_block)

#     return bytes(plaintext)


# with open("flag.enc", "rb") as ff:
#     print(decrypt_ecb(list(ff.read()), key))
