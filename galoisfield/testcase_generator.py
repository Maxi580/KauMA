from galoisfieldelement import GaloisFieldElement
from galoisfieldpolynomial import GaloisFieldPolynomial
from block_poly.block import Block

gfp = GaloisFieldPolynomial([GaloisFieldElement(1), GaloisFieldElement(1)]).to_b64_list()
k = 3
result = GaloisFieldPolynomial([GaloisFieldElement(1)]).to_b64_list()

print(gfp)

print(result)