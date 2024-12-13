from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.block import Block
from constants import ENCRYPT_MODE
from crypto_algorithms.fde import apply_fde
from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt


def fde_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64(arguments["key"]).block
    tweak = B64(arguments["tweak"]).block
    input_data = B64(arguments["input"]).block
    encrypt = mode == ENCRYPT_MODE

    result = apply_fde(key, tweak, input_data, encrypt)

    return {"output": Block(result).b64}
