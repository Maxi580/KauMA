from collections.abc import Callable

from utils import xor_bytes
from constants import BLOCK_SIZE
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial


def _poly_to_bytes(poly: GaloisFieldPolynomial, original_length: int) -> bytes:
    result = bytearray()
    for gfe in poly:
        result.extend(gfe.to_block_gcm())
    return result[:original_length]


def apply_key_stream(text: bytes, key: bytes, nonce: bytes, encryption_algorithm: Callable) -> bytes:
    result = bytearray()

    ctr = 2
    for i in range(0, len(text), BLOCK_SIZE):
        yi = nonce[-12:] + ctr.to_bytes(4, byteorder='big')

        key_block = encryption_algorithm(key, yi)
        text_block = text[i:i + BLOCK_SIZE]

        result.extend(xor_bytes(key_block[:len(text_block)], text_block))

        ctr += 1

    return result


def get_auth_key(key: bytes, encryption_algorithm: Callable) -> GaloisFieldElement:
    zero_block = bytes(BLOCK_SIZE)
    encrypted_block = encryption_algorithm(key, zero_block)
    return GaloisFieldElement.from_block_gcm(encrypted_block)


def get_eky0(key: bytes, nonce: bytes, encryption_algorithm: Callable) -> GaloisFieldElement:
    ctr = 1
    y0 = nonce[-12:] + ctr.to_bytes(4, byteorder='big')
    encrypted_block = encryption_algorithm(key, y0)

    return GaloisFieldElement.from_block_gcm(encrypted_block)


def get_ghash(h: GaloisFieldElement, ad: GaloisFieldPolynomial, ciphertext: GaloisFieldPolynomial,
              l: GaloisFieldElement) -> GaloisFieldElement:
    zero_block = bytes(BLOCK_SIZE)
    X = GaloisFieldElement.from_block_gcm(zero_block)

    for gfe in ad:
        X += gfe
        X *= h

    for gfe in ciphertext:
        X += gfe
        X *= h

    X += l
    X *= h
    return X


def get_l(ad: bytes, ciphertext: bytes) -> GaloisFieldElement:
    ad_bit_length = len(ad) * 8
    cipher_bit_length = len(ciphertext) * 8

    l = ad_bit_length.to_bytes(8, byteorder='big') + cipher_bit_length.to_bytes(8, byteorder='big')
    return GaloisFieldElement.from_block_gcm(l)


def calculate_tag(key: bytes, ad: bytes, ciphertext: bytes, nonce: bytes, encryption_algorithm: Callable) \
        -> tuple[GaloisFieldElement, GaloisFieldElement, GaloisFieldElement]:

    # Turning ciphertext and ad into a poly automatically pads them (which we don´t want for ciphertext/ plaintext calc)
    ciphertext_poly = GaloisFieldPolynomial.from_block(ciphertext)
    ad_poly = GaloisFieldPolynomial.from_block(ad)

    auth_key = get_auth_key(key, encryption_algorithm)
    l = get_l(ad, ciphertext)
    ghash = get_ghash(auth_key, ad_poly, ciphertext_poly, l)
    eky0 = get_eky0(key, nonce, encryption_algorithm)
    tag = ghash + eky0

    return tag, l, auth_key


def gcm_encrypt(encryption_algorithm: Callable, nonce: bytes, key: bytes, plaintext: bytes, ad: bytes) \
        -> tuple[bytes, bytes, bytes, bytes]:

    ciphertext = apply_key_stream(plaintext, key, nonce, encryption_algorithm)

    tag, l, auth_key = calculate_tag(key, ad, ciphertext, nonce, encryption_algorithm)

    return ciphertext, tag.to_block_gcm(), l.to_block_gcm(), auth_key.to_block_gcm()


def gcm_decrypt(nonce: bytes, key: bytes, ciphertext: bytes, ad: bytes, provided_auth_tag: bytes,
                encryption_algorithm: Callable) -> tuple[bool, bytes]:

    plaintext = apply_key_stream(ciphertext, key, nonce, encryption_algorithm)

    tag, _, _ = calculate_tag(key, ad, ciphertext, nonce, encryption_algorithm)

    return tag.to_block_gcm() == provided_auth_tag, plaintext
