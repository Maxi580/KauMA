from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial, degree

ONE = GaloisFieldPolynomial([GaloisFieldElement(1)])
X = GaloisFieldPolynomial([GaloisFieldElement(0), GaloisFieldElement(1)])


def ddf(f: GaloisFieldPolynomial) -> list[tuple[GaloisFieldPolynomial, int]]:
    q = 1 << 128
    d = 1
    z = []
    fstar = f
    while degree(fstar) >= 2 * d:
        h = (pow(X, (q ** d), fstar) - X) % fstar

        g = GaloisFieldPolynomial.gcd(h, fstar)
        if g != ONE:
            z.append((g, d))
            fstar = fstar // g
        d += 1

    if fstar != ONE:
        z.append((fstar, degree(fstar)))
    elif len(z) == 0:
        z.append((f, 1))
    return sorted(z)
