from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from block_poly.b64_block import B64Block
from server import check_pkcs7_padding


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


plaintext = bytes.fromhex('4974207265616c6c7920776f726b7321')
#padded_plaintext = pkcs7_pad(plaintext)

key = bytearray(16)
iv = B64Block("dxTwbO/hhIeycOTbTnp8QQ==").block

cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)

decryptor = cipher.decryptor()
ciphertext = decryptor.update(plaintext) + decryptor.finalize()

print(f"Plaintext: {plaintext}")  # b'This thing works'
print(f"Key: {key}")  # b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
print(f"IV: {iv}")  # b'w\x14\xf0l\xef\xe1\x84\x87\xb2p\xe4\xdbNz|A'
print(f"Ciphertext: {ciphertext}")  # b'V\x0c\x91\x1f\xa8\xcf\xd3\xfa\xc3\xbbM\x9f\x97\xd04d'

#[b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002']

message = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000'
decryptor = cipher.decryptor()
test = decryptor.update(message) + decryptor.finalize()
print(f"Decrypted Test: {test}")