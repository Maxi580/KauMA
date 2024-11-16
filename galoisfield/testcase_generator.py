from galoisfieldelement import GaloisFieldElement
from galoisfieldpolynomial import GaloisFieldPolynomial

gfp = GaloisFieldPolynomial([GaloisFieldElement(1)]).to_b64_list_gcm()
k = 1000

print(gfp)
