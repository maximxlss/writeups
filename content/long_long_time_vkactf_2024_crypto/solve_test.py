from pathlib import Path
from sage.all import *
from utils import *
import random


modulus = 294275658183003798500620082226653851949
SIZE = 20
coefs = [
    56808825511620403721980107922655004035,
    186275623444214810044468111617842771804,
    19674422692868805958155796261974088674,
    88706226686312397477978680205574659458,
    63204032571502179220213286165123720644,
    208997874749986655953052128290580041769,
    157342135024512213550816727840088401549,
    42563802965199053365308284625730859231,
    101462328015573471760208508836308231868,
    264825846671258377714480642662517485559,
    116777634448334556114608464874746366704,
    104365399460131847169957563418525550564,
    92068545857911151716390826674844059569,
    149646099191354363982827079760066845746,
    263622125847991285012037520505380080838,
    256099355596279322208576291661592811556,
    220623498188574396099999644344000063868,
    215460366107865119196338370391435063757,
    130320271167685960874620675849457325321,
    36052789998334355324366454757592776147,
]
inits = [
    78116438772248306476699672500118164890,
    275423064417102445652768442354462786403,
    101884405442106709062674588737049451066,
    100296844188475776780284504324256410496,
    48843150737216497333859900231149762052,
    227443353636371814038371089440572611020,
    255381961856314755723112710177992514307,
    16657337879536428986153153556831424508,
    55570987504138992451220652598665402436,
    183011926800748976074215610274354320745,
    1919835746141577239465276133804053418,
    169056417844382119285169523526802694849,
    119798124772738032435593260521086354354,
    162376723852480006604039117960002930077,
    259580135184152896869754997896760416145,
    210905126928473454612535060272729105390,
    179493973380370031201717508730689409369,
    263827756629553096619263791991586215559,
    129122934832149408609498104967344416851,
    221632397007969709283803840151244600082,
]


# test closed form

for n in range(1337, 1337 + 10):
    assert calc_terms(modulus, coefs, inits, n) == calc_terms_slow(
        modulus, coefs, inits, n
    )

# test log

closed_form, roots, closed_form_coefs = recover_closed_form(modulus, coefs, inits)

for e in range(1337, 1337 + 20):
    result = [closed_form(j - 1) for j in range(e + 1, e + 1 + len(coefs))]
    assert e == int(solve_log(result, roots, closed_form_coefs))


# gen task

Na = random.randint(0, modulus)
Nb = random.randint(0, modulus)

pub_a = calc_terms(modulus, coefs, inits, Na + 1)
pub_b = calc_terms(modulus, coefs, inits, Nb + 1)

S_a = calc_terms(modulus, coefs, pub_b, Na + 1)
S_b = calc_terms(modulus, coefs, pub_a, Nb + 1)

assert S_a == S_b

# solve

closed_form, _, _ = recover_closed_form(modulus, coefs, inits)

assert pub_b == [closed_form(j - 1) for j in range(Nb + 1, Nb + 1 + SIZE)]

closed_form, roots, closed_form_coefs = recover_closed_form(modulus, coefs, pub_b)

assert Na == int(solve_log(S_b, roots, closed_form_coefs))

for i in range(Na, Na + SIZE):
    assert closed_form(i) == S_b[i - Na]


print("All tests passed")
