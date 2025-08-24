---
title: The Field of Wonders (PSUTI CTF 2025; crypto)
date: 2025-08-24
tags:
  - crypto
  - crypto/aead
  - crypto/lattices
  - crypto/algebra
  - difficulty/hard
---
> Author: xSDark
> Все же слышали про "Поле Чудес"? Я создал его, но только для крипто-игроков. Веселитесь.

files: [here](https://github.com/maximxlss/writeups/tree/v4/content/field_of_wonders/files/).

Hello! Welcome to my writeup on a very interesting challenge I have solved at PSUTI CTF 2025. This challenge is primarily about the XChaCha20-Poly1305 scheme, with the exploit using linear algebra and lattices. If you like that stuff, you will probably enjoy this article.

Before heading straight into it, I want to thank the author for this challenge, I have had much fun solving it. 

### The challenge
I won't get into the details on the task's code, let's get straight into the core problem we need to solve:

It's made quite obvious that you need to learn to somehow guess a passphrase by issuing up to 6 requests to the `open_word` function. The function tries this with the given `word_ctxt`:
```Python
secret.Aead(self.key).decrypt(bytes.fromhex(word_ctxt))
```
(The key is derived from the passphrase. There are only 125 possible passphrases)

We get a binary output: either the decryption succeeds (we don't get the result) or it fails. 

> [!QUESTION]- What is AEAD?
> AEAD (Authenticated encryption with associated data) - is a class of encryption schemes that come with a MAC (Message authentication code). That means you can trust the authenticity of the message out of the box: a person without the key can not forge any new encrypted messages (that would pass the check).
> Compare this to AES-CTR, for example: CTR makes flipping bits in the ciphertext do the same for the corresponding plaintext, which means an attacker may forge a particular message without decrypting it or having the key.

You might notice that the function actually allows us to check if a particular key is correct or not, since we can just encrypt with it and submit. If the check succeeds, the key is correct.

If not for the request limit, we could've just go through all 125 of them and find the right one. Considering the limit, we have to find another way.

Let's make another interesting observation: every call to the function only gives us 1 bit of information. That means that we can (at most) filter out only half of the possibilities per call. Halving 125 six times is actually not enough: you would still have to guess between two possibilities. The task is deliberately made to not allow you to guess, since you have to pass the passphrase check 35 times in a row. So the task seems unsolvable just through this function.

> [!QUESTION]- Why the random module is not exploitable?
> Due to the lack of information you might consider trying to infer information from the Mersenne Twister weakness. But if you examine the [source code](https://github.com/python/cpython/blob/6fcac09401e336b25833dcef2610d498e73b27a1/Modules/_randommodule.c), you can check that it is not actually helpful. The first 624 outputs (before the twist) are just tampered numbers from the seed, which is taken from urandom (a good source).

As it turns out, the function checks the number of calls incorrectly! When I noticed it (just before I gave up on the challenge) I immediately figured it's probably intentional. Let's see why I guessed that.
 
### How is binary search related
**Technically, we can do something like a binary search to pinpoint a single value of 125 total in just 7 queries.** But that's not considering the real situation. How do we turn the decryption into such a check? Still, not much else to work with, so even though it sounds impossible, we have to try it.

### ~~ChaCha20~~-Poly1305
The AEAD scheme itself sounds scary, but it's really not. Look at the [Wikipedia page](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). There is a helpful diagram that shows that we actually don't care about ChaCha20, the only thing that's relevant is Poly1305. Still, it looks like the tag directly depends on the key, which is not helping considering we're trying to make data such that the tag is the same for multiple keys.

Let's look further into Poly1305: [another Wikipedia page](https://en.wikipedia.org/wiki/Poly1305). Basically, it works like this:
- Divide the message into blocks, pad them and use those as polynomial coefficients, denote the polynomial $p(x)$.
- Derive $r$ and $s$ from the key and the nonce.
- Calculate: $(p(r)\pmod{2^{130} - 5} + s)\pmod{2^{128}}$ - this is the tag.

So, the _polynomial_ comes from the message, and the _argument_ comes from the key. This is quite helpful. 

To make a key verify the message (given a tag $a$), you just have to make this true: $p(r)\pmod{2^{130} - 5}=a-s\pmod{2^{128}}$. Clearly, this is easy to do even for many keys, especially considering there's practically no bound on the polynomial degree, you just have to use any kind of interpolation. If only we could just directly specify the polynomial...

But we can't. Let's start small. Here are all the resources I used to precisely determine the input format:
- [Wikipedia](https://en.wikipedia.org/wiki/Poly1305)
- [Pycryptodome source](https://github.com/Legrandin/pycryptodome/blob/master/src/poly1305.c)
- [libsodium source](https://github.com/jedisct1/libsodium/blob/def5b9d306c3707255b948ac10885dc880184efe/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c)

Reusing some Pycryptodome functions, I extracted the logic that determines the r and s values from a key. From those it's easy to construct a list of points: $(r_i, -s_i\ \%\ 2^{128})$. If our polynomial would match those points then the tag would be zero for the corresponding keys: $p(r_i)+s_i=-s_i+s_i=0$.

A couple more things to notice about the polynomial coefficients:
- The most significant byte is set to be 1, we can't control it.
- The constant term is always zero.

The latter can be satisfied by adding a point: $(0, 0)$. The former I satisfied by just altering the parameters until it matched. At this point you can do Lagrange interpolation on the points (with a bit of luck for the last bytes) and get a working example of a text with needed properties. Feeding it directly into Poly1305 would indeed work as intended. But this is not enough to solve the task, for two reasons:
- The probability of hitting all the right ending bytes is too low for bigger degree (which we need to hit the 60 keys simultaneously).
- There is additional padding added after the text, which means there are more coefficients fixed.

This means we need some more advanced machinery to satisfy all the constraints.

> [!info]- What is the ciphertext format?
> This has caused me a lot pain figuring out. Here it is:
> $\overbrace{\text{key mask}\,||\,\text{actual nonce}}^{\text{nonce}}\,||\,\text{the ciphertext itself}\,||\,\text{MAC}$
> Key mask is used to mask the key (this is actually relevant for the r, s derivation)
> The actual nonce is actually padded with 4 zeros on the left (the derivation function accepts 12-byte nonces)

> [!info]- What is actually fed into Poly1305?
> $\text{AAD}\,||\,\text{the provided ciphertext}\,||\,\text{AAD len (4-byte)}\,||\,\text{CT len (4-byte)}$
> AAD is empty in our case, AAD len = 0
> This means there is one additional fixed coefficient, equal to $\text{AAD len}\,||\,\text{CT len}$.

### Constructing polynomials with constraints on the coefficients
Let's formalize the problem. Let's assume we already have a polynomial $p(x)$ (`base_poly` in code, which we get from the simple interpolation) and a set of points $\{x_i\}$ (`points` in code), and we want to _modify_ the polynomial to make it fit the constraints while not changing it's value at each $x_i$.

Let's then formulate it like this: find a polynomial $d(x)$ such that $d(x_i)=0$ for each point and $p(x) + d(x)$ satisfies the constraints. Obviously, $p(x) + d(x)$ matches $p(x)$ at the points $\{x_i\}$.

We'll have to deal with two kinds of constraints. First of all, some coefficients have to exactly equal a value. Secondly, others have to have a right ending byte (must be $2^{128} + d$ with $d < 2^{128}$). The former is easy to deal with, the latter we'll have to reformulate a bit. We'll say that they have to be close to $2^{128} + 2^{127}$ (no farther than $2^{127}$ away).[^2] This is equivalent.

Overall, if we consider the coefficients as a vector $v$, we have a target vector $t$, where for some coordinates we need it to be equal and for some just close. Why consider those as vectors?[^1] Polynomial addition can be considered coefficient-wise! Denote the coefficient vector of $p$ as $c_p$, then $v=c_p+c_d$ and we can shift to finding the $d$ polynomial by changing the target to $t-c_p$. Now the problem is to find a polynomial not with certain _values_, but certain _zeros_.

This is easier, since all polynomials with those zeros can be expressed as $f(x)(x-x_0)(x-x_1)\dots(x-x_n)$. Denote $a(x)=(x-x_0)(x-x_1)\dots(x-x_n)$ (`aux_poly` in code). Consider some polynomials of the form given: $a(x), a(x)\cdot x, a(x)\cdot x^2,\dots$ Any polynomial with given zeros would be possible to express as a linear combination of those polynomials. By taking only a finite amount of those, we limit the degree to a sensible value.

Construct a matrix $B$ with those polynomials' coefficient vectors as columns. Notice that this matrix gives us a coefficient vector for a polynomial with fitting zeros for any vector you multiply by it (since matrix-vector multiplication is basically calculating a linear combination). This means a vector we're searching for lies somewhere in it's _column space_.

We'll start by getting the first constraint type out of the way.[^3] Let's extract the rows corresponding to the coefficients which are fixed and get a smaller matrix $B'$. We'll get an underdetermined system of equations (in matrix form) which we can solve and get a vector $u_1$ such that $Bu_1$ at least satisfies those constraints. From linear algebra you might know that there are more solutions, more precisely, any vector from $\text{Ker}(B') + u_1$ fits (a fancy way to say that not changing the constrained coefficients doesn't break the solution). We just now have to choose a vector $u$ from this space to get $Bu$ to fit other constraints too.

First of all, let's shift the target vector yet again, now by $-Bu_1$. This reduces the problem to finding a vector $u_2$ from the $\text{Ker}(B')$ close to the target (since it's in the kernel, the exact constraints do not matter here, they would be satisfied anyway). After finding this vector, $B(u_1 + u_2) + с_p$ (here, $B(u_1 + u_2)$ is the aforementioned $d(x)$'s coefficient vector) would match the constraints.

We'll first get a basis for this $\text{Ker}(B')$ space. Now we'll construct the lattice consisting of this space's image under $B$. This lattice basically consists of all the coefficient vectors of polynomials with the right zeros, but with zero coefficients for the coefficients with exact constraints. In this lattice, we solve CVP to find a vector close to the constraints. This would be the $Bu_2$ vector. If the degree is enough, it would probably be close enough. We then sum up the vectors and get the coefficient vector we were searching for.

In reality, this is made considerably less complicated by the fact that there are only two fixed constraints both on one side of the vector. A basis for the kernel is also just all but first two polynomials, since only those affect the first coefficients. Besides, CVP solver from fplll is too slow and the parameters are quite nice so we just use Babai's nearest plane algorithm. Look at the code for more details.

Let's go over the main points again:
- We're finding a polynomial to _add_ to $p(x)$ with zeros at points we don't want to change.
- The constraints are all based on a certain target coefficient list, so we can reduce the problems to finding unknown terms by shifting the target.
- Coefficients of a polynomial may be thought of as a vector.
- Multiplication of polynomials $ab$ (retains zeros) is basically finding a linear combination of shifted copies of $a$ (so that also retains zeros).
- Finding a linear combination is basically matrix-vector multiplication (which also represents a certain system of equations)
- We fulfill the exact constraints by solving a system of equations normally.
- We then reduce the problem to finding the solution to inexact constraints, not forgetting to restrict it to a certain kernel so the exact constraints still match.
- This problem is basically lattice CVP.
- We then go back and construct the final vector, which is the coefficient vector for a polynomial matching all the constraints.

At this point, we can construct the polynomial we wanted. This allows us to check if a set contains the right key or not. This is due to our polynomial providing the same tag on all the keys we constructed it for. 

We then just do a kind of binary search on the keys and find the right one in at most 7 queries.

### Afterthoughts
I'm pretty sure this solution is quite a bit more complicated than it has to be, but I have outlined a very general and quite powerful technique for constructing polynomials with constraints, so I hope this is still helpful.

Thank you for reading!

[^1]: Personally, I'm always associating this trick with the Coppersmith's method. The steps after (in turning polynomial multiplication into matrix-vector multiplcation) are also similar.

[^2]: Motivated by CVP

[^3]: This should be possible to skip and integrate in the lattice somehow (?)
