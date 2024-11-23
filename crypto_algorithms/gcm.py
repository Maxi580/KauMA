from collections.abc import Callable

from block_poly.block import Block
from constants import BLOCK_SIZE
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial


def _poly_to_bytes(poly: GaloisFieldPolynomial, original_length: int) -> bytes:
    result = bytearray()
    for gfe in poly:
        result.extend(gfe.to_block_gcm())
    return result[:original_length]


def get_key_stream(size: int, key: bytes, nonce: bytes, encryption_algorithm: Callable) -> GaloisFieldPolynomial:
    key_stream = GaloisFieldPolynomial([])

    ctr = 2
    for i in range(0, size, BLOCK_SIZE):
        yi = nonce[-12:] + ctr.to_bytes(4, byteorder='big')
        gfe = GaloisFieldElement.from_block_gcm(encryption_algorithm(key, yi))
        key_stream.add_elements(gfe)
        ctr += 1

    return key_stream


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


def get_l(ad_len: int, ciphertext_len: int) -> GaloisFieldElement:
    ad_bit_length = ad_len * 8
    cipher_bit_length = ciphertext_len * 8

    l = ad_bit_length.to_bytes(8, byteorder='big') + cipher_bit_length.to_bytes(8, byteorder='big')
    return GaloisFieldElement.from_block_gcm(l)


def calculate_tag(key: bytes, ciphertext_len: int, ad_len: int, ad: GaloisFieldPolynomial,
                  ciphertext: GaloisFieldPolynomial, nonce: bytes, encryption_algorithm: Callable) \
        -> tuple[GaloisFieldElement, GaloisFieldElement, GaloisFieldElement]:
    auth_key = get_auth_key(key, encryption_algorithm)
    l = get_l(ad_len, ciphertext_len)  # unnecessary to calculate back length of a gfp, plaintext length is the same
    ghash = get_ghash(auth_key, ad, ciphertext, l)
    eky0 = get_eky0(key, nonce, encryption_algorithm)
    tag = ghash + eky0

    return tag, l, auth_key


def gcm_encrypt(encryption_algorithm: Callable, nonce: bytes, key: bytes, plaintext_bytes: bytes, ad_bytes: bytes) \
        -> tuple[bytes, bytes, bytes, bytes]:
    ad_len = len(ad_bytes)  # After Blocks are converted to Polys, it gets hard to get original length (padding etc.)
    text_len = len(plaintext_bytes)

    plaintext = GaloisFieldPolynomial.from_block(plaintext_bytes)
    ad = GaloisFieldPolynomial.from_block(ad_bytes)

    key_stream = get_key_stream(text_len, key, nonce, encryption_algorithm)
    ciphertext = key_stream + plaintext

    tag, l, auth_key = calculate_tag(key, text_len, ad_len, ad, ciphertext, nonce, encryption_algorithm)

    # When turning to poly, the original size gets lost so we need to trim it back
    ciphertext = _poly_to_bytes(ciphertext, text_len)
    return ciphertext, tag.to_block_gcm(), l.to_block_gcm(), auth_key.to_block_gcm()


def gcm_decrypt(nonce: bytes, key: bytes, ciphertext_bytes: bytes, ad_bytes: bytes,
                provided_auth_tag: bytes, encryption_algorithm: Callable) \
        -> tuple[bool, bytes]:
    ad_len = len(ad_bytes)
    text_len = len(ciphertext_bytes)

    ciphertext = GaloisFieldPolynomial.from_block(ciphertext_bytes)
    ad = GaloisFieldPolynomial.from_block(ad_bytes)
    provided_auth_tag = GaloisFieldElement.from_block_gcm(provided_auth_tag)

    key_stream = get_key_stream(text_len, key, nonce, encryption_algorithm)
    plaintext = key_stream + ciphertext

    tag, _, _ = calculate_tag(key, text_len, ad_len, ad, ciphertext, nonce, encryption_algorithm)

    # When turning to poly, the original size gets lost so we need to trim it back
    plaintext = _poly_to_bytes(plaintext, text_len)
    return tag == provided_auth_tag, plaintext
