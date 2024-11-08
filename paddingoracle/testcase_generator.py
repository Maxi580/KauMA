from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from block_poly.block import Block
import secrets


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


plaintext = pkcs7_pad(b'Hello')

key = b'\xeeH\xe0\xf4\xd0c\xeb\xd8\xb87\x16\xd3\t\xfe\x87\xce'
iv = secrets.token_bytes(16)

cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

print(f"Plaintext: {Block(plaintext).b64_block}")
print(f"Key: {Block(key).b64_block}")
print(f"IV: {Block(iv).b64_block}")
print(f"Ciphertext: {Block(ciphertext).b64_block}")


decryptor = cipher.decryptor()
ciphertext = decryptor.update(ciphertext) + decryptor.finalize()

print(ciphertext)