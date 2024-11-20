from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial


def sff(f: GaloisFieldPolynomial):
    f_derived = f.diff()
    c = GaloisFieldPolynomial.gcd(f, f_derived)
    f = f / c

    z = []
    exponent = 1
    while f != GaloisFieldPolynomial([GaloisFieldElement(1)]):
        y = GaloisFieldPolynomial.gcd(f, c)

        if f != y:
            z.append((f / y, exponent))

        f = y
        c = c / y
        exponent += 1

    if c != GaloisFieldPolynomial([GaloisFieldElement(1)]):
        for (fstar, estar) in sff(c.sqrt()):
            z.append((fstar, estar * 2))
    return z
