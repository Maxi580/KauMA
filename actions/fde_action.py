from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.block import Block
from crypto_algorithms.fde import encrypt_fde, decrypt_fde
from constants import ENCRYPT_MODE


def fde_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64(arguments["key"]).block
    tweak = B64(arguments["tweak"]).block
    input_data = B64(arguments["input"]).block

    result = encrypt_fde(key, tweak, input_data) if mode == ENCRYPT_MODE else decrypt_fde(key, tweak, input_data)

    return {"output": Block(result).b64}
