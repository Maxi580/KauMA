from typing import Dict, Any


def block2poly_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from block_poly.b64 import B64
    from constants import XEX_SEMANTIC

    block = arguments["block"]
    semantic = arguments["semantic"]

    result = B64(block).xex_coefficients if semantic == XEX_SEMANTIC else B64(block).gcm_coefficients

    return {"coefficients": result}


def poly2block_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # Using Shabby imports for 3x Performance Improvement. I'm sorry.
    from block_poly.coefficients import Coefficients
    from constants import XEX_SEMANTIC

    coefficients = arguments["coefficients"]
    semantic = arguments["semantic"]

    result = Coefficients.from_xex_semantic(coefficients) if semantic == XEX_SEMANTIC else (
        Coefficients.from_gcm_semantic(coefficients))

    return {"block": result.b64}
