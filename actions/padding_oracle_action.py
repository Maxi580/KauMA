from typing import Dict, Any

from block_poly.b64 import B64
from block_poly.block import Block
from paddingoracle.paddingOracle import recover_padding_oracle_plaintext


def padding_oracle_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    hostname = arguments["hostname"]
    port = arguments["port"]
    iv = B64(arguments["iv"]).block
    ciphertext = B64(arguments["ciphertext"]).block

    plaintext = recover_padding_oracle_plaintext(ciphertext, iv, hostname, port)

    return {"plaintext": Block(plaintext).b64}
