from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

ONE = GaloisFieldPolynomial([GaloisFieldElement(1)])


def sff(f: GaloisFieldPolynomial) -> list[tuple[GaloisFieldPolynomial, int]]:
    f_derived = f.diff()
    c = GaloisFieldPolynomial.gcd(f, f_derived)
    f = f / c

    z = []
    exponent = 1
    while f != ONE:
        y = GaloisFieldPolynomial.gcd(f, c)

        if f != y:
            z.append((f / y, exponent))

        f = y
        c = c / y
        exponent += 1

    if c != ONE:
        for (fstar, estar) in sff(c.sqrt()):
            z.append((fstar, estar * 2))
    return sorted(z)
