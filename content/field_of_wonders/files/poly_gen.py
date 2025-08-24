from sage.all import *
from fpylll import IntegerMatrix, CVP, LLL, GSO
from fpylll.algorithms import babai


def get_auxtext(text_len):
    return b''.join([x.to_bytes(8, 'little') for x in [0, text_len]])

def generate_data(base_poly, points, opt_degree=20):
    N = 2 ** 130 - 5
    ZMOD = Zmod(N)

    PR = PolynomialRing(ZMOD, "x")
    x = PR.gen()

    base_coefs = vector(list(base_poly))
    aux_poly = product((x - p) for p in points)

    polys = [aux_poly * x ** i for i in range(opt_degree)]

    coefs_list = [list(poly) for poly in polys]

    width = max(len(poly) for poly in coefs_list)

    coefs_list = [poly + [0] * (width - len(poly)) for poly in coefs_list]

    base_coefs = vector([*base_coefs] + [0] * (width - len(base_coefs)))

    B = matrix(ZMOD, coefs_list).T

    data = int.from_bytes(get_auxtext(B.nrows() * 16 - 32), 'little')

    need = vector(ZMOD, [0, 2 ** 128 + data]) - base_coefs[:2]
    mini_system = B[:len(need), :]

    sol = mini_system.solve_right(need)
    res = B * sol

    need = (vector(ZMOD, [2 ** 128 + 2 ** 127] * width) - base_coefs - res)[2:]
    aval = B.T[2:, 2:]
    reduced_B = block_matrix(ZZ, [
        [aval],
        [identity_matrix(width - 2) * N]
    ])

    reduced_B = reduced_B.echelon_form()
    while reduced_B[-1].is_zero():
        reduced_B = reduced_B[:-1]

    A_int = IntegerMatrix.from_matrix([[int(reduced_B[i][j]) for j in range(reduced_B.ncols())] for i in range(reduced_B.nrows())])

    need_int = [int(x) for x in need]

    A = LLL.reduction(A_int)
    M = GSO.Mat(A)
    M.update_gso()
    # v0 = CVP.closest_vector(A, need_int)
    v0 = babai.babai(A, need_int)


    sol2 = aval.T.solve_right(vector(v0))

    sol = sol + vector([0, 0, *sol2])
    res = B * sol + base_coefs

    # print(res)
    assert all(int(x).to_bytes(17, 'little')[-1] == 1 for x in res[1:])

    generated_poly = PR(list(res))

    # print(generated_poly)

    assert all(generated_poly(x0) == base_poly(x0) for x0 in points)

    # print(b''.join(int(x).to_bytes(17, 'little')[:-1] for x in reversed(res[1:])))

    return b''.join(int(x).to_bytes(17, 'little')[:-1] for x in reversed(res[2:]))
