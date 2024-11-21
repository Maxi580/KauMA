import secrets

from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial, degree
from constants import BLOCK_SIZE

ONE = GaloisFieldPolynomial([GaloisFieldElement(1)])


def generate_random_poly(max_degree: int):
    new_poly = GaloisFieldPolynomial([])
    new_degree = secrets.randbelow(max_degree)

    for i in range(new_degree):
        new_poly.add_elements(GaloisFieldElement.from_block_gcm(secrets.token_bytes(BLOCK_SIZE)))

    return new_poly


def edf(f: GaloisFieldPolynomial, d: int) -> list[GaloisFieldPolynomial]:
    q = 1 << 128
    n = degree(f) // d
    z = [f]
    max_random_degree = degree(f) - 1

    while len(z) < n:
        h = generate_random_poly(max_random_degree)
        g = (pow(h, (q ** d - 1) // 3, f) - ONE) % f

        for u in z:
            if degree(u) > d:
                j = GaloisFieldPolynomial.gcd(u, g)
                if j != ONE and j != u:
                    z.remove(u)
                    z.append(j)
                    z.append(u // j)

    return sorted(z)
