import secrets

from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from constants import BLOCK_SIZE

ONE = GaloisFieldPolynomial([GaloisFieldElement(1)])
X = GaloisFieldPolynomial([GaloisFieldElement(0), GaloisFieldElement(1)])


def _generate_random_poly(max_degree: int):
    new_poly = GaloisFieldPolynomial([])
    new_degree = secrets.randbelow(max_degree)

    for i in range(new_degree):
        new_poly.add_elements(GaloisFieldElement.from_block_gcm(secrets.token_bytes(BLOCK_SIZE)))

    return new_poly


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
    max_random_degree = f.degree - 1

    while len(z) < n:
        h = _generate_random_poly(max_random_degree)
        g = (pow(h, (q ** d - 1) // 3, f) - ONE) % f

        for u in z:
            if u.degree > d:
                j = u.gcd(g)
                if j != ONE and j != u:
                    z.remove(u)
                    z.append(j)
                    z.append(u // j)

    return sorted(z)


def find_roots(f: GaloisFieldPolynomial):
    roots = []
    for factor_sff in sff(f):
        f_sff = factor_sff[0]

        for factor_ddf in ddf(f_sff):
            f_ddf = factor_ddf[0]
            degree = factor_ddf[1]

            if degree == f_ddf.degree:
                roots.append(f_ddf)
            else:
                roots.extend(edf(f_ddf, degree))
    return roots
