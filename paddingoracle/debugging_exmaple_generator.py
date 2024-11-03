from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from server import check_pkcs7_padding


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding


plaintext = bytes.fromhex('4974207265616c6c7920776f726b7321')
#padded_plaintext = pkcs7_pad(plaintext)

key = bytearray(16)
iv = bytearray(16)

cipher = Cipher(
    algorithms.AES(key),
    modes.CBC(iv),
    backend=default_backend()
)

encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

print(f"Plaintext: {plaintext}")  # b'It really works!'
print(f"Key: {key}")  # b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
print(f"IV: {iv}")  # b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
print(f"Ciphertext: {ciphertext}")  # b'V\x0c\x91\x1f\xa8\xcf\xd3\xfa\xc3\xbbM\x9f\x97\xd04d'

#[b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002']
#  It really works!