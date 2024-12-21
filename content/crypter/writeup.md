---
title: Crypter (Russian CTF Cup 2024 Final; A/D, crypto)
draft: false
tags: []
date: 2024-12-21
---
Fun service I focused on the CTF Cup this year. Time spent amounts to about 7 hours lol

### The beginning part
This service instantly caught my attention as it was seemingly cryptography based, and I was delighted to find a custom Paillier implementation and plenty of suspicious crypto code. I was not too happy to see C++ there, but I'm okay with that if it means there's crypto (no pwn tho, sadge 😢).

I have to confess that I was quite unfamiliar with Paillier at that moment. Though I have [some trauma](https://github.com/C4T-BuT-S4D/ctfcup-2023-quals/tree/master/tasks/crp/lateralus) connected with it, so I did notice the $(n + 1)^m\pmod{n^2}$.

If you want to look at the service yourself, I have it in [this repo](https://github.com/maximxlss/writeups/tree/v4/content/crypter/source).

### The service part
The service is pretty simple, written in C++ using gRPC, gmp and Postgres. The basic parts are as follows:
- Basic user management. On registering you get a personal token for sending messages, a typical random $n=pq$ public key as well as a private key in the form of totient $\phi(n)=(p - 1)(q - 1)$. This process is not secure; we'll get to that later. The public keys of other people are stored in the database, accessible to anyone.
- Messages. You can send a message, list messages sent to you or get a message by id (no matter who it is for). The messages are all encrypted when sent using the DIY cryptosystem we'll examine later. There is no service for decryption (the private key is not even saved server-side).
- Cryptosystem. It's an implementation of [Paillier cryptosystem](https://en.wikipedia.org/wiki/Paillier_cryptosystem) with gmp, seemingly secure lol. You can read about how it works in detail elsewhere, I won't explain it much here.

### The easy part
A more obvious oversight that was found by many is easy to notice when you examine the `random_integer` function:
```C
uint8_t seed = device();
```
This is the only non-deterministic input into the prng, so it's not that hard to just recover all the 256 possible results and find the factors of `n` in there. After that you just need to figure out the decryption process and you're done. This was exploited starting from the first two hours of the game, so I won't get into the details much.

Sadly it took me some time to notice this stuff (I was blinded by the other stuff), so we lost quite a lot because of this vuln.

### The hard part
Now we get to the fun stuff, basically no one found the other, intended, vuln. There are a couple of suspicious oversights you can notice in the code:
- `mpz_class r = random_integer(32);` - The `r` value is not as long as `n` but rather half as long. Sadly, I did not find this fact useful in any way.
- Errors seem to be returned to the user, could've been useful but in no way here.
- The message is _small_, only 128 bits. Absolutely tiny in comparison with the other parameters.
- `return res1 * res2;` - Hmm, no `% n2` there. 6000 bits of information instead of the expected 4096 🤔

Over the course of the ctf I tried a ton of stuff: expanding stuff, dividing stuff, googling stuff, putting stuff into automatic tools.
As it turns out, I've been walking in circles. I have noticed how you can consider `res1` to be equal to $1 + nm$, how you can get part of $\text{mod}(r^n, n^2)$ by taking $\text{mod}\ n$ and had a feeling Coppersmith's method is to be used, but the puzzle just didn't connect in my head.

After a couple of hours I was considering that there is actually no other vuln in this service and I'm just wasting time, but the obvious mistakes in the code just bothered me too much...

The event was nearing it's end. I went to take a break, after that I sat down and... I just found it? I actually couldn't believe it.

In the end, here's a direct path to solution:
- Notice how the encoded message takes the following form: $\text{mod}((1 + n)^m, n^2) \cdot \text{mod}(r^n, n^2)$.
- According to the main idea of Paillier, we can rewrite the first part like this: $\text{mod}(1 + nm, n^2) \cdot \text{mod}(r^n, n^2)$.
- Notice how $1 + nm < n$, so we can further simplify to $(1 + nm) \cdot \text{mod}(r^n, n^2)$.
- Now, let's rename the other multiplier to just $R$; we get $(1 + nm) \cdot R$.
- Notice how $\text{mod}((1 + nm) \cdot R, n) = \text{mod}(R, n)$, call it $e$. Then you can express $R$ as $kn + e$ for some $k$.
- Look at the resulting expression: $(1 + nm)(kn + e)=kmn^2 + kn + emn + e$. $n$ and $e$ are known, $k$ and $m$ are only about 2200 bits total, when the value we get is about 6000 bits. This hints at possible Coppersmith method usage; as it turns out, it works!

### The other part
The exploit setup is also interesting:
- First, you need to install gRPC and generate the stubs. More info on that in the [official docs](https://grpc.io/docs/languages/python/quickstart/).
- The exploit requires sagemath too. That's not enough still: it only runs from inside the [crypto-attacks repository](https://github.com/jvdsn/crypto-attacks) since I have no idea how Coppersmith's method works exactly, so I'm using the implementation smart people published.
- This how the last-minute exploit looks like:
```Python
#!/usr/bin/env python3

from sage.all import *
from primefac import primefac

path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(os.path.abspath(__file__)))))
if sys.path[1] != path:
    sys.path.insert(1, path)

from shared.small_roots import coron

from crypter_pb2 import *
from crypter_pb2_grpc import *
from requests import get
from random import shuffle
import sys


sys.set_int_max_str_digits(999999)

ip = sys.argv[1]


data = get("https://cbsctf.live/api/client/attack_data/").json()
ids = [s.removeprefix("{\"message\": \"").removesuffix("\"}") for s  in data["crypter"][ip]]

with grpc.insecure_channel(f'{ip}:2112') as channel:
    stub = CrypterStub(channel)
    for msg_id in ids:
        message = stub.GetMessage(GetMessageRequest(id=str(msg_id)))
        public_key = stub.GetUserPublicKey(GetUserPublicKeyRequest(username=message.username))
        n = int(public_key.n)
        ct = int(message.encrypted)
        e = ct % n

        PR = PolynomialRing(ZZ, "m, k")
        m, k = PR.gens()

        poly = m * k * n ** 2 + m * e * n + k * n + e - ct

        sol = coron.integer_bivariate(poly, 1, 2 ** 128, 2 ** 2048)

        for sol in sol:
            m, k = sol
            print(int(m).to_bytes((int(m).bit_length() + 7) // 8, 'big'), flush=True)
```

The moment I deployed it, we got about 5000 points in just one round, jumping from 10th to 6th in just a moment! Sadly, I solved it too late to actually make a difference.
