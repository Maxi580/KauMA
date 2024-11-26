import random

from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from crypto_algorithms.gcm import get_l, get_ghash
from gcm_crack.gcm_types import GCMMessage, GCMForgery

ONE = GaloisFieldPolynomial([GaloisFieldElement(1)])
X = GaloisFieldPolynomial([GaloisFieldElement(0), GaloisFieldElement(1)])


def _generate_random_poly(max_degree: int):
    new_poly = GaloisFieldPolynomial([])
    new_degree = random.randint(0, max_degree - 1)

    for i in range(new_degree):
        new_poly.add_elements(GaloisFieldElement(random.randint(1, (1 << 128) - 1)))

    return new_poly


def _find_correct_h(h_candidates: list[GaloisFieldElement], m1: GCMMessage, m3: GCMMessage) \
        -> tuple[GaloisFieldElement, GaloisFieldElement]:
    for potential_auth_key in h_candidates:
        # Calculate back the ek0 for the given auth key, stays the same due to same nonce etc.
        m1_l = get_l(m1.ad_bytes, m1.ciphertext_bytes)
        m1_ghash = get_ghash(potential_auth_key, m1.associated_data, m1.ciphertext, m1_l)
        ek0 = m1_ghash + m1.tag

        # Try to authenticate m3 with potential auth key
        m3_l = get_l(m3.ad_bytes, m3.ciphertext_bytes)
        m3_ghash = get_ghash(potential_auth_key, m3.associated_data, m3.ciphertext, m3_l)
        tag = ek0 + m3_ghash

        # If Tag is the same, authentication is successful
        if tag == m3.tag:
            return potential_auth_key, ek0


def sff(f: GaloisFieldPolynomial) -> list[tuple[GaloisFieldPolynomial, int]]:
    f_derived = f.diff()
    c = f.gcd(f_derived)
    f = f // c
    z = []
    exponent = 1

    while f != ONE:
        y = f.gcd(c)

        if f != y:
            z.append((f // y, exponent))

        f = y
        c = c // y
        exponent += 1

    if c != ONE:
        for (fstar, estar) in sff(c.sqrt()):
            z.append((fstar, estar * 2))
    return sorted(z)


def ddf(f: GaloisFieldPolynomial) -> list[tuple[GaloisFieldPolynomial, int]]:
    q = 1 << 128
    d = 1
    z = []
    fstar = f

    while fstar.degree >= 2 * d:
        h = (pow(X, (q ** d), fstar) - X) % fstar
        g = h.gcd(fstar)
        if g != ONE:
            z.append((g, d))
            fstar = fstar // g
        d += 1

    if fstar != ONE:
        z.append((fstar, fstar.degree))
    elif len(z) == 0:
        z.append((f, 1))
    return sorted(z)


def edf(f: GaloisFieldPolynomial, d: int) -> list[GaloisFieldPolynomial]:
    q = 1 << 128
    n = f.degree // d
    z = [f]

    while len(z) < n:
        h = _generate_random_poly(f.degree)
        g = (pow(h, (q ** d - 1) // 3, f) - ONE) % f

        for u in z:
            if u.degree > d:
                j = u.gcd(g)
                if j != ONE and j != u:
                    z.remove(u)
                    z.append(j)
                    z.append(u // j)

    return sorted(z)


def recover_h(f: GaloisFieldPolynomial, m1, m3):
    """Combines Root finding and checking if they are a correct H
       We do this because we don't want to continue root searching, after we found correct H"""
    for factor_sff in sff(f):
        f_sff = factor_sff[0]

        for factor_ddf in ddf(f_sff):
            f_ddf = factor_ddf[0]
            degree = factor_ddf[1]

            if degree == f_ddf.degree:
                # Root is found (= f_ddf), check if it is a correct solution
                result = _find_correct_h([f_ddf[0]], m1, m3)
                if result:
                    return result
            else:
                roots = [root[0] for root in edf(f_ddf, degree)]
                # Roots are found => check if they are a correct solution
                result = _find_correct_h(roots, m1, m3)
                if result:
                    return result

    raise ValueError("No valid h value found that satisfies the given messages")
