from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.poly import Poly
from galoisfield.galoisfieldelement import GaloisFieldElement
from constants import XEX_SEMANTIC


def gfmul_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    a = arguments["a"]
    b = arguments["b"]
    semantic = arguments["semantic"]

    a_poly = B64(a).xex_poly if semantic == XEX_SEMANTIC else B64(a).gcm_poly
    b_poly = B64(b).xex_poly if semantic == XEX_SEMANTIC else B64(b).gcm_poly

    int_result = int(GaloisFieldElement(a_poly) * GaloisFieldElement(b_poly))
    b64_result = Poly.from_xex_semantic(int_result).b64 if semantic == XEX_SEMANTIC else (
        Poly.from_gcm_semantic(int_result).b64)

    return {"product": b64_result}
