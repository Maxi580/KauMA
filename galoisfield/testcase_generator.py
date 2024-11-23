from galoisfieldelement import GaloisFieldElement
from galoisfieldpolynomial import GaloisFieldPolynomial
from block_poly.block import Block

gfp = GaloisFieldPolynomial([GaloisFieldElement(1), GaloisFieldElement(1)]).to_b64()
k = 3
result = GaloisFieldPolynomial([GaloisFieldElement(1)]).to_b64()

print(gfp)

print(result)