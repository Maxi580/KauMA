from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from block_poly.b64_block import B64Block
from server import check_pkcs7_padding


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


plaintext = pkcs7_pad(b'Hello There Does it Really Really Work?')

key = bytearray(16)
iv = B64Block("dxTwbO/hhIeycOTbTnp8QQ==").block

cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

print(f"Plaintext: {plaintext}")
print(f"Key: {key}")
print(f"IV: {iv}")
print(f"Ciphertext: {ciphertext}")


decryptor = cipher.decryptor()
ciphertext = decryptor.update(ciphertext) + decryptor.finalize()

print(ciphertext)