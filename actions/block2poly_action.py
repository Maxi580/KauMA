from typing import Dict, Any


def block2poly_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from block_poly.b64 import B64
    from constants import XEX_SEMANTIC

    block = arguments["block"]
    semantic = arguments["semantic"]

    result = B64(block).xex_coefficients if semantic == XEX_SEMANTIC else B64(block).gcm_coefficients

    return {"coefficients": result}
