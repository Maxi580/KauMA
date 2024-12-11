from typing import Dict, Any


def poly2block_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    from block_poly.coefficients import Coefficients
    from constants import XEX_SEMANTIC

    coefficients = arguments["coefficients"]
    semantic = arguments["semantic"]

    result = Coefficients.from_xex_semantic(coefficients) if semantic == XEX_SEMANTIC else (
        Coefficients.from_gcm_semantic(coefficients))

    return {"block": result.b64}
