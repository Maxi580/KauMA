from typing import Dict, Any, Final

from block_poly.b64 import B64
from block_poly.block import Block
from crypto_algorithms.sea128 import sea_encrypt, aes_encrypt
from crypto_algorithms.gcm import gcm_encrypt, gcm_decrypt

AES_128_ALGORITHM: Final[str] = "aes128"


def gcm_encrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64(arguments["nonce"]).block
    key = B64(arguments["key"]).block
    plaintext = B64(arguments["plaintext"]).block
    ad = B64(arguments["ad"]).block

    encryption_algorithm = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    ciphertext, tag, l, auth_key = gcm_encrypt(encryption_algorithm, nonce, key, plaintext, ad)

    return {"ciphertext": Block(ciphertext).b64, "tag": Block(tag).b64, "L": Block(l).b64,
            "H": Block(auth_key).b64}


def gcm_decrypt_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    algorithm = arguments["algorithm"]
    nonce = B64(arguments["nonce"]).block
    key = B64(arguments["key"]).block
    ciphertext = B64(arguments["ciphertext"]).block
    ad = B64(arguments["ad"]).block
    tag = B64(arguments["tag"]).block

    encrypt_function = aes_encrypt if algorithm == AES_128_ALGORITHM else sea_encrypt

    authentic, plaintext = gcm_decrypt(nonce, key, ciphertext, ad, tag, encrypt_function)

    return {"authentic": authentic, "plaintext": Block(plaintext).b64}
