---
title: Skill Diff (L3akCTF 2025; crypto)
date: 2025-07-12
tags:
  - crypto
  - crypto/differential
  - crypto/symmetric
  - difficulty/medium
---

Greetings! After the sphinx challenge from Google CTF 2025, I took interest in differential cryptanalysis, so I was happy to try and solve this one. Here I'll describe my solution, which seems to be one of the most efficient ways to solve this challenge, so I hope it will be interesting to you. Let's get straight into it.

### The challenge
The challenge includes a couple of files. This is due to the distribution including both the optimized C code as well as a SageMath file. Having a fast implementation allows the input limit on the remote to be a whopping 60 MB, from which (spoiler alert) I used a suprisingly little amount of 64 KB.

I'll be using Python with SageMath. My code, edited and expanded from `chall.sage`, can be found [here](https://github.com/maximxlss/writeups/tree/v4/content/solve_diff/solve.py).

I will index everything from 0. Let's also define $\mathbf{e}_i$ by $\mathbf{e}_i[j]=\begin{cases}1 & j=i \\ 0 & \text{otherwise}\end{cases}$.

The cipher uses four round keys. The first one is the provided key, others are derived from it with SHA-256. Let's denote those byte vectors $K_i$.

The other components are:
- a binary invertible 16x16 matrix $M$. Although $(Mv)[15]=v[1]$, this did not prove to be helpful in my attack.
- an $sbox: Z_{256}^8\to Z_{256}^8$. Seemingly, it does not have useful features.
- a collection of 16 linear functions $\text{aff}_i(x)=A_ix+B_i$.
- I'll denote $f_i(x)=\text{sbox}(\text{aff}_i(x)\oplus 1)$ for numbers and $f(v)=u$ when $u[i]=f_i(v[i])$ for vectors.

All the arithmetic with bytes is done modulo $256$.

The encryption consists of three rounds. If $v_i$ denotes the state after round $i$, then $v_0=\text{pt} + K_0$ and $v_i = f(Mv_{i - 1}) + K_{i + 1}$. Finally, $\text{ct}=v_3$.

### The idea
First of all, notice how $\Delta(Mv_0) = M\Delta\text{pt}$ and so we may as well look for differentials from that point in the cipher. The multiplication by $M$ is the only source of diffusion, so $\Delta v_1$ is then similar to $M\Delta\text{pt}$ (the zeros are the same).

What if $\Delta v_1=a\mathbf{e}_i+b\mathbf{e}_j$? Then $\Delta v_2$ is similar to $M(a\mathbf{e}_i+b\mathbf{e}_j)=aM\mathbf{e}_i+bM\mathbf{e}_j$.

This fact turns out to be very helpful. Since $M$ is binary, both $M\mathbf{e}_i$ and $M\mathbf{e}_j$ are binary as well. So $aM\mathbf{e}_i+bM\mathbf{e}_j$ consists only of components equal to $0, a, b$ or $a + b$. So there are two possible patterns of zeros here, depending on if $a + b = 0$ or not. If we can distinguish those, we get an important piece of information about $a$ and $b$.

Luckily, $M$ is sparse enough that, in the last multiplication, it maps many of those patterns to distinct patterns in the output. For example, here is one of the applicable characteristics:

$$
\begin{array}{|l|cccccccccccccccc|}
\hline
\text{Vector} & \\ \hline
\Delta v_1 & a & 0 & 0 & b & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 & 0 \\
M\Delta v_1 & 0 & 0 & b & b & 0 & 0 & (a+b)^* & 0 & 0 & (a+b)^* & 0 & 0 & 0 & a & a & 0 \\
\Delta v_2 & 0 & 0 & ? & ? & 0 & 0 & ?^* & 0 & 0 & ?^* & 0 & 0 & 0 & ? & ? & 0 \\
\Delta\text{ct} & ? & ? & ? & ? & 0 & 0 & ? & ?^* & 0 & ? & ?^* & ?^* & ? & ? & ? & 0 \\
\hline
\end{array}
$$
Values marked with an asterisk ${}^*$ are zero when $a+b=0$ and are (usually) nonzero when $a+b\ne 0$. There are three such places in the ciphertext, so it will be a good guess that the probability of all three of those being zero when $a+b\ne 0$ is $(2^{-8})^3=2^{-24}$, which suggests that over all $2^{16}$ of the pairs this is a good way to identify the "right" ones. While we're at it, the probability of hitting $a+b=0$ is $2^{-8}$, so we can expect around $2^8$ of those over all of the pairs.

So now we can get a bunch of pairs with $a+b=0$. But what are $a$ and $b$? Remember, $\Delta v_1 = a\mathbf{e}_i+b\mathbf{e}_j$, so (call $x=M\text{pt}$, $k=MK_0$)
$$
\begin{align*}
a &= \Delta v_1[i]\\
&=\Delta f(Mv_0)[i]\\
&=\Delta f(x+k)[i]\\
&=\Delta f_i(x[i]+k[i])
\end{align*}
$$
Similarly, $b=\Delta f_j(x[j]+k[j])$.

So $a+b=0$, aka $a=-b$ really means $\Delta f_i(x[i]+k[i])=-\Delta f_j(x[j]+k[j])$. $\Delta f_j(x[j]+k[j])$ is close to being injective in terms of $k[j]$, so we can construct a relatively small collection of possible pairs $(k[i], k[j])$. I built a certain LUT to speed it up.

This is only for a single pair, but clearly we can get more of those! As you might guess, only the real pair of $(k[i], k[j])$ appears for every one of those collections. In reality, due to false right pairs and other things, it's not in 100% of them, but is still easily identifiable.

By analyzing a couple of right pairs for each index, we can recover $k$ and so $K_0=M^{-1}k$, which is the master key, so we're done here.

### The implementation
To make the attack more efficient and easier to code, considering we must encrypt everything we want at once, I used this structure:
```Python
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

pts_collections = [gen_pts(base, i) for i in range(16)]
```
This allows to get a pair for any 2-place difference in $Mv_0$ we might want. This is just $256\cdot 16=4096$ plaintexts, or 64 KB.

Here are the functions I used to bruteforce the characteristics:
```Python
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
```
Characteristics with only 1 distinguishing byte are expected to provide more false right pairs then real ones, so they are discarded. There are fitting characteristics for all bytes, except for the 15-th. I just bruteforced that byte directly, as you will see.

Constructing the LUTs:
```Python
def diffs_lut(i):
    diffs = {}
    for dx in range(256):
        if dx not in diffs:
            diffs[dx] = {}
        for x in range(256):
            diffs[dx][(f(i, (x + dx) % 256) - f(i, x)) % 256] = x
    return diffs

diffs_luts = [diffs_lut(i) for i in range(16)]
```
It would be a bit better to consider all possible $x$ values here, but I just went with the simple and fast solution.

Finding right pairs:
```Python
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
```
This could be a bit faster without directly trying all the pairs, but isn't really worth it.

Finding a single byte.
```Python
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
```
Pretty neat and fast. 50 matches for a right pair is an arbitrary number, but it works fine.

The final steps:
```Python
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
```

To actually get the ciphertexts inside the program, I just made it to write a file with the plaintexts and ask me to encrypt it.

### Afterthoughts
In reality, a couple of right pairs is enough, so you can just cut on the encryptions and it will still work. The byte which has to be bruteforced anyway can be skipped, too. I was able to easily reduce it to just $64 \cdot 15 = 960$ encryptions, or 15 KB. 

Theoretically, just two right pairs is expected to be enough, and we can skip another byte since $2^{16}$ is not a lot. So, the expected theoretical amount of ciphertext is even lower: 322 blocks, or a little over 5 KB, while retaining about the same compute.

I want to note that, besides being efficient, this is one of the most complicated ways to solve this task! I'm not (yet) experienced in differential cryptanalysis, so I'm kind of rolling my own. Make sure to check out the other solutions for more interesting crypto!


