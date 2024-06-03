from functools import lru_cache
from sage.all import *
from sys import setrecursionlimit

setrecursionlimit(99999)


def recover_closed_form(modulus, coefs, inits):
    SIZE = len(coefs)
    F = GF(modulus)
    (x,) = PolynomialRing(F, "x").gens()
    characteristic = x**SIZE - sum(
        F(coef) * x ** (SIZE - i - 1) for i, coef in enumerate(coefs)
    )
    SF = characteristic.splitting_field("a")
    roots = characteristic.roots(SF)
    roots = [(root, i) for root, mul in roots for i in range(mul)]

    mat = matrix(
        SF,
        [[SF(i) ** j * root**i for root, j in roots] for i, init in enumerate(inits)],
    )
    vec = vector(SF, [SF(init) for i, init in enumerate(inits)])
    closed_coefs = mat.solve_right(vec)

    def resulting_closed_form(n):
        return sum(
            coef * n**i * root**n for (root, i), coef in zip(roots, closed_coefs)
        )

    return resulting_closed_form, roots, closed_coefs


def solve_log(values, roots, coefs):
    SF = roots[0][0].base_ring()
    SIZE = len(roots)
    double_root = next(x for x, _ in roots if (x, 0) in roots and (x, 1) in roots)
    single_roots = [x for x, _ in roots if x != double_root]
    assert len(single_roots) == SIZE - 2

    double_root_coefs = [
        coef for (root, _), coef in zip(roots, coefs) if root == double_root
    ]
    single_root_coefs = [
        coef for (root, _), coef in zip(roots, coefs) if root != double_root
    ]
    mat = []

    for d, result in enumerate(values):
        row = []
        for root, coef in zip(single_roots, single_root_coefs):
            row.append(coef * root**d)
        row.append(
            double_root_coefs[0] * double_root**d
            + double_root_coefs[1] * d * double_root**d
        )
        row.append(double_root_coefs[1] * double_root**d)
        mat.append(row)

    mat = matrix(SF, mat)
    vec = vector(SF, [SF(result) for i, result in enumerate(values)])
    sol = mat.solve_right(vec)

    return int(sol[-1] / sol[-2])


@lru_cache(maxsize=None)
def linear_recurrence(m, n, initial_terms, coefficients):
    if len(initial_terms) != len(coefficients):
        raise ValueError(
            "Число начальных членов и коэффициентов должно быть одинаковым"
        )

    if n <= len(initial_terms):
        return initial_terms[n - 1]

    result = 0
    for i in range(len(initial_terms)):
        result += coefficients[i] * linear_recurrence(
            m, n - i - 1, initial_terms, coefficients
        )

    return result % m


def calc_terms(modulus, coefs, inits, i):
    closed_form, _, _ = recover_closed_form(modulus, coefs, inits)
    return [closed_form(j - 1) for j in range(i, i + len(coefs))]


def calc_terms_slow(modulus, coefs, inits, i):
    return [
        linear_recurrence(modulus, j, tuple(inits), tuple(coefs))
        for j in range(i, i + len(coefs))
    ]
