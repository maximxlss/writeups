---
title: SDES++ (San Diego CTF 2024; crypto)
date: 2024-05-13
---
>Author: 18lauey2
>(For the easier version) I heard DES was broken, so I wrote SDES - San Diego Encryption Standard. It has a key space of 2^64 - no one's ever going to break it... right?
>
>(For the harder version) Okay okay, this time I'm going to generate a new session key every time I encrypt it. No way you're breaking it _this_ time.

Given:
1. https://github.com/acmucsd/sdctf-2024/tree/main/crypto/sdes/dist
2. https://github.com/acmucsd/sdctf-2024/tree/main/crypto/sdes-plus-plus/dist

### Common part
The cipher operates byte-by-byte, applying a bunch of sboxes to them. Let's assume a fixed unknown key and observe. The crucial part in the solution is that, almost always, incrementing the key changes **only the first box**, which means  