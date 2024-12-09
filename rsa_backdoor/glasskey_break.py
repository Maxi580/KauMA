from cryptography.x509 import load_der_x509_certificate
from pyasn1.codec.der.decoder import decode
from rsa_backdoor.modules.pyasn1_modules import ContentInfo, EnvelopedData
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Tuple

from rsa_backdoor.glasskey import Glasskey
from rsa_backdoor.rsa import decrypt_rsa, generate_rsa_key, RSAKey


def _extract_private_rsa_key(x509_crt: bytes, agency_key: bytes) -> RSAKey:
    cert = load_der_x509_certificate(x509_crt)

    # extract modulo n
    public_key = cert.public_key()
    public_numbers = public_key.public_numbers()
    n = public_numbers.n

    # topmost 64 bit of modulo are seed
    seed = n >> (n.bit_length() - 64)
    assert seed.bit_length() == 64, "seed length is wrong"

    # Now we can calculate private key, because its deterministic
    gk = Glasskey(agency_key, seed.to_bytes(8, byteorder='big'))
    p, q = gk.genkey(1024)

    return generate_rsa_key(p, q)


def _decode_cms(encoded_cms: bytes) -> Tuple[bytes, bytes, bytes]:
    decoded_cms = decode(encoded_cms, asn1Spec=ContentInfo())
    cms_msg: ContentInfo = decoded_cms[0]

    decoded_content = decode(bytes(cms_msg["content"]), asn1Spec=EnvelopedData())
    enveloped_data = decoded_content[0]

    encrypted_key = bytes(enveloped_data["recipientInfos"][0]["ktri"]["encryptedKey"])
    iv = bytes(
        enveloped_data["encryptedContentInfo"]["contentEncryptionAlgorithm"][
            "parameters"
        ][2:]  # Remove Metadata
    )
    ciphertext = bytes(enveloped_data["encryptedContentInfo"]["encryptedContent"])

    return encrypted_key, iv, ciphertext


def _remove_padding(padded_session_key: bytes) -> bytes:
    """Remove PKCS#1 v1.5 padding, standardized padding scheme for RSA encryption"""

    assert padded_session_key[0] == 0 and padded_session_key[1] == 2, "Invalid PKCS#1 v1.5 padding"

    # Find the end of padding (first zero byte after the second byte)
    separator_index = padded_session_key.find(b'\x00', 2)
    assert separator_index > 0, "Invalid PKCS#1 v1.5 padding"

    return padded_session_key[separator_index + 1:]


def _decrypt_message(rsa_private_key: RSAKey, encrypted_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # Recover Session Key
    padded_session_key = decrypt_rsa(rsa_private_key, encrypted_key)
    session_key = _remove_padding(padded_session_key)

    # Create AES cipher with Session key
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    return plaintext


def glasskey_break(x509_crt: bytes, agency_key: bytes, cms_msg: bytes) -> bytes:
    """1. Extract the key from cert, 2. decode/ extract values from cms message, 3. crack plaintext"""
    rsa_key = _extract_private_rsa_key(x509_crt, agency_key)
    encrypted_key, iv, ciphertext = _decode_cms(cms_msg)
    plaintext = _decrypt_message(rsa_key, encrypted_key, iv, ciphertext)

    return plaintext
