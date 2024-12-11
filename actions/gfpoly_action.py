from typing import Dict, Any


def gfpoly_add_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    S = A + B

    return {"S": S.to_b64()}


def gfpoly_mul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    S = A * B

    return {"P": S.to_b64()}


def gfpoly_pow_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    k = arguments["k"]
    A = GaloisFieldPolynomial.from_b64(arguments["A"])

    Z = A ** k

    return {"Z": Z.to_b64()}


def gfdiv_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldelement import GaloisFieldElement
    from block_poly.poly import Poly
    from block_poly.b64 import B64

    a = B64(arguments["a"]).gcm_poly
    b = B64(arguments["b"]).gcm_poly

    q = int(GaloisFieldElement(a) / GaloisFieldElement(b))

    return {"q": Poly.from_gcm_semantic(q).b64}


def gfpoly_divmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    a = GaloisFieldPolynomial.from_b64(arguments["A"])
    b = GaloisFieldPolynomial.from_b64(arguments["B"])

    Q, R = divmod(a, b)

    return {"Q": Q.to_b64(), "R": R.to_b64()}


def gfpoly_powmod_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    A = arguments["A"]
    M = arguments["M"]
    k = arguments["k"]

    gfp_a = GaloisFieldPolynomial.from_b64(A)
    gfp_m = GaloisFieldPolynomial.from_b64(M)

    Z = pow(gfp_a, k, gfp_m)

    return {"Z": Z.to_b64()}


def gfpoly_sort_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    b64_polys = arguments["polys"]
    polys = [GaloisFieldPolynomial.from_b64(b64_poly) for b64_poly in b64_polys]

    sorted_polys = sorted(polys)

    b64_sorted_polys = [poly.to_b64() for poly in sorted_polys]

    return {"sorted_polys": b64_sorted_polys}


def gfpoly_make_monic_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    A.make_monic()

    return {"A*": A.to_b64()}


def gfpoly_sqrt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    Q = GaloisFieldPolynomial.from_b64(arguments["Q"])
    sqrt_Q = Q.sqrt()

    return {"S": sqrt_Q.to_b64()}


def gfpoly_diff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    F = GaloisFieldPolynomial.from_b64(arguments["F"])
    derived_F = F.diff()

    return {"F'": derived_F.to_b64()}


def gfpoly_gcd_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial

    A = GaloisFieldPolynomial.from_b64(arguments["A"])
    B = GaloisFieldPolynomial.from_b64(arguments["B"])

    result = A.gcd(B)

    return {"G": result.to_b64()}


def gfpoly_factor_sff_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
    from gcm_crack.recover_h import sff

    F = GaloisFieldPolynomial.from_b64(arguments["F"])
    result = sff(F)

    return {"factors": [{"factor": result[i][0].to_b64(), "exponent": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_ddf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
    from gcm_crack.recover_h import ddf

    F = GaloisFieldPolynomial.from_b64(arguments["F"])
    result = ddf(F)

    return {"factors": [{"factor": result[i][0].to_b64(), "degree": result[i][1]} for i in range(len(result))]}


def gfpoly_factor_edf_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
    from gcm_crack.recover_h import edf

    F = GaloisFieldPolynomial.from_b64(arguments["F"])
    d = arguments["d"]

    result = edf(F, d)

    return {"factors": [result[i].to_b64() for i in range(len(result))]}
