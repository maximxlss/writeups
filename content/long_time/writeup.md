---
title: Long Long Time (VKA CTF 2024; crypto)
draft: false
tags: []
date: 2024-06-03
---
> Автор: Inssurg3nt
> Один из жителей, наплевав на все ограничения, запустил этот скрипт в далеком 1987 году, когда переехал в город-Z, и вот наконец-то он отработал и выдал нам результат! Правда, он забыл добавить вывод ключа...

> Author: Inssurg3nt
> One of the residents, ignoring all the restrictions, ran this script back in 1987, when he moved to city Z, and finally it completed execution and displayed the result! However, he forgot to display the key...
Task files: [`give`](https://github.com/maximxlss/writeups/tree/v4/content/long_time/give)
Solve script: [`solve.py`](https://github.com/maximxlss/writeups/blob/v4/content/long_time/solve.py)
### Truly a long time
The task contains the script that supposedly completed execution since 1987. It contains a VERY inefficient implementation of a linear recurrence in $\mathbb{Z}_p$ (aka integers modulo a prime) that can barely compute itself at $n=32$, let alone the values used, which are around $2^{128}$ (yes, 37 years is not even close to being enough).
The script is appropriately named `DH.py`, as it does do [Diffie-Hellman key exchange](https://brilliant.org/wiki/diffie-hellman-protocol/), except it uses a linear recurrence: both parties calculate the terms corresponding to their private keys, exchange those values and advance the recurrence starting at what they got from the other party. It's plain to see that this algorithm does generate a valid shared key.
### Cool, and...?
Basically, we are Bob and we need to recover Alice's secret. This amounts to inverting the recurrence (calculating $n$), analogous to the discrete logarithm problem for classic DH. As we will see later down the line, this problem actually is equivalent to computing a certain discrete logarithm.
### Fibonacci, but not quite
Linear recurrence reminded me of [lateralus](https://github.com/C4T-BuT-S4D/ctfcup-2023-quals/tree/master/tasks/crp/lateralus). This is an interesting task, which involves inverting a _closed-form solution_ for Fibonacci sequence in $\mathbb{Z}_{p^2}$ to obtain a discrete logarithm problem, which can be solved using a clever trick. It's actually very similar to what we have here, as the Fibonacci sequence is a prime example of a **linear recurrence with constant coefficients** (but the coefficients in it are ones). There is a helpful wiki page about those: [click](https://en.wikipedia.org/wiki/Linear_recurrence_with_constant_coefficients). This page contains everything needed to make the script _fast_.
### Characteristic polynomial
Imagine a recurrence:
$$
f(n)=a_1f(n-1)+a_2f(n-2)+\cdots+a_kf(n-k)
$$
As per that wiki page, we are interested in this polynomial, called _characteristic_ (letting recurrence coefficients equal $a_i$):
$$
p(x)=x^k-a_1x^{k-1}-a_2x^{k-2}-\cdots-a_k
$$
It's roots $x_i$ partially define the _closed form_ of the recurrence:
$$
f(n)=c_1x_1^n+c_2x_2^n+\cdots+c_kx_k^n
$$
$c_i$ are dependent on the starting values of the recurrence.
> [!NOTE] For example, Fibonacci:
> Recurrence: $f(n)=f(n-1)+f(n-2)$
> Characteristic polynomial: $p(x)=x^2-x-1;\ p(\phi)=0,\ p(\psi)=0$
> Closed form: $f(n)=c_1\phi^n+c_2\psi^n$
> As it turns out, for starting values $f(0)=0;\ f(1)=1$ we have $c_1=-c_2=\frac{1}{\sqrt{5}}$
> So, in the end, we have: $f(n)=\frac{\phi^n-\psi^n}{\sqrt{5}}$
### Praise Sagemath
Let's start by finding the roots:
```Python
F = GF(modulus)
(x,) = PolynomialRing(F, "x").gens()
characteristic = x**SIZE - sum(
	F(coef) * x ** (SIZE - i - 1) for i, coef in enumerate(coefs)
)
roots = characteristic.roots()
```
You should get $k$ roots, accounting for multiplicities.
> [!NOTE] Lacking roots?
> Sometimes[^1], you might not get the expected $k$ roots. There may even be no roots at all! That doesn't mean the recurrence is unsolvable. Instead, it makes it even more interesting :)
> This situation is similar to the familiar reals $\mathbb{R}$. If we don't have enough roots, we just make it a bit more _complex_, switching over to an _extension field_ $\mathbb{C}$, aka $\mathbb{R}[i]$ ($\mathbb{R}$ _adjoint_ $i$).
> In the case of $\mathbb{Z}_p$ (or $GF(p)$, equivalently), the extension is $GF(p^n)$ (which is **not** integers modulo $p^n$ but something like a polynomial ring over $\mathbb{Z}_p$), and it can be automatically found by sagemath (as always):
> ```Python
> SF = characteristic.splitting_field("a")
> print(SF) # Finite Field in a of size 17^13
> roots = characteristic.roots(SF, multiplicities=False)
> # [a ^ 7 + 10*a^3 + 10, ... ] (not a real example)
> ```
> [^1]: Even though this doesn't happen in this task (or you have just confused the order of coefficients as I did at first), I really wanted to include this here to showcase how there are natural extensions for $GF(p)$.

Now we only need to find $c_i$ values. Consider the equations for the (known) starting values:
$$
f(0)=c_1x_1^0+c_2x_2^0+\cdots+c_kx_k^0
$$
$$
f(1)=c_1x_1^1+c_2x_2^1+\cdots+c_kx_k^1
$$
$$
\vdots
$$
$$
f(k - 1)=c_1x_1^{k - 1}+c_2x_2^{k - 1}+\cdots+c_kx_k^{k - 1}
$$
In terms of the unknowns $c_i$ this is a linear system, which can be solved [in terms of matrices](https://ask.sagemath.org/question/33574/solve-linear-system-in-gf7/), as usual:
```Python
mat = matrix(
	SF,
	[[root**i for (root, mul) in roots] for i, init in enumerate(inits)],
)
vec = vector(SF, [SF(init) for i, init in enumerate(inits)])
closed_form_coefs = mat.solve_right(vec)
```
Now we have everything needed to assemble the closed form solution to the recurrence:
```Python
def closed_form(n):
	return sum(
		coef * root**n for (root, mul), coef in zip(roots, closed_form_coefs)
	)
```
### What now?
We have the terms $f(n),\ f(n+1),\cdots,\ f(n+d)$ at our disposal. Let's see what kind of equations we are working with (let n be the secret, which we want to find out):
$$
f(n)=c_1x_1^n+c_2x_2^n+\cdots+c_kx_k^n
$$
$$
f(n+1)=c_1x_1^{n+1}+c_2x_2^{n+1}+\cdots+c_kx_k^{n+1}
$$
$$
\vdots
$$
$$
f(n+d)=c_1x_1^{n+d}+c_2x_2^{n+d}+\cdots+c_kx_k^{n+d}
$$
After some simple algebraic manipulation:
$$
f(n)=c_1x_1^n+c_2x_2^n+\cdots+c_kx_k^n
$$
$$
f(n+1)=c_1x_1x_1^n+c_2x_2x_2^n+\cdots+c_kx_kx_k^n
$$
$$
\vdots
$$
$$
f(n+d)=c_1x_1^dx_1^n+c_2x_2^dx_2^n+\cdots+c_kx_k^dx_k^n
$$
If we (similarly to lateralus!) focus on $x_i^n$, this turns into a linear system again. Except in lateralus, the resulting discrete log was in $\mathbb{Z}_{p^2}$, which allowed to calculate it efficiently.
This time, the problem is in $\mathbb{Z}_{p}$ (and $p-1$ isn't smooth), so it's practically unsolvable. So no luck, huh...
### Not so fast!
Actually, if the coefficients were random, that would've been true. But in reality, I lied to you. In this task the coefficients are special: there is a double root for the characteristic polynomial. That makes the closed form a bit different (let $x_1$ be the double root):
$$
f(n)=c_1x_1^n+c_2nx_1^n+\cdots+c_kx_{k-1}^n
$$
The process of finding the coefficients is practically the same (see solve script).
### Is that even worse? Or...
You might think there's no way having $n$ both in the exponent and in the coefficient is better:
$$
f(n)=c_1x_1^n+c_2nx_1^n+\cdots+c_kx_{k-1}^n
$$
$$
f(n+1)=c_1x_1^{n+1}+c_2(n+1)x_1^{n+1}+\cdots+c_kx_{k-1}^{n+1}
$$
$$
\vdots
$$
$$
f(n+d)=c_1x_1^{n+d}+c_2(n+d)x_1^{n+d}+\cdots+c_kx_{k-1}^{n+d}
$$
But just look at how we can again choose $k$ variables to make the system linear:
$$
f(n)=c_1x_1^n+c_2nx_1^n+\cdots+c_kx_{k-1}^n
$$
$$
f(n+1)=(c_1x_1+c_2x_1)x_1^n+c_2x_1nx_1^n+\cdots+c_kx_{k-1}x_{k-1}^n
$$
$$
\vdots
$$
$$
f(n+d)=(c_1x_1^d+c_2dx_1^d)x_1^n+c_2x_1^dnx_1^n+\cdots+c_kx_{k-1}^dx_{k-1}^n
$$
See it? The variables are $x_i^n$ and a special one $nx_1^n$. So we bypass discrete logarithm entirely by solving this system and calculating $\frac{nx_1^n}{x_1^n}$ !

Problem is, this _doesn't work at all_ for the values given...
### Please check your tasks...
The reason turns out to be that in process of constructing the output of the script that _supposedly_ was ran, the author somehow swapped the order of the given terms, ruining the solution. I have spent _hours_ looking for a non-existent bug in my program just because of that.
```Python
S_b.reverse()
```
. . .
Run [`solve_test.py`](https://github.com/maximxlss/writeups/blob/v4/content/long_time/solve_test.py) to verify that the method works for a random $n$.
### Anyway, how did it happen?
I don't know. This probably was more reasonable for them, because their solution is very different. The proposed solution uses matrices all the way, as there is a way to express the recurrence as matrix multiplication, and the given values are a special case in which calculating the logarithm is easy. The corresponding math is [Linear Recurrences](https://gciruelos.com/linear-recurrences.html) and [Jordan normal form](https://en.wikipedia.org/wiki/Jordan_normal_form).
There is definitely a deeper connection between my solution and theirs, but I'm yet to think that through.

Anyway, this is all I wanted to tell, thank you for reading!