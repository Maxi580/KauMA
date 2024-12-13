from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.block import Block
from crypto_algorithms.sea128 import sea_encrypt, sea_decrypt
from constants import ENCRYPT_MODE


def sea128_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    mode = arguments["mode"]
    key = B64(arguments["key"]).block
    input_data = B64(arguments["input"]).block

    result = sea_encrypt(key, input_data) if mode == ENCRYPT_MODE else sea_decrypt(key, input_data)

    return {"output": Block(result).b64}
