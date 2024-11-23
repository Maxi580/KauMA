from dataclasses import dataclass

from block_poly.b64_block import B64
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement
from gcm.bruteforce_test import ciphertext
from crypto_algorithms.gcm import get_l, get_ghash, get_auth_key
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from gcm.find_roots import find_roots


@dataclass
class GCMMessage:
    ciphertext: GaloisFieldPolynomial
    associated_data: GaloisFieldPolynomial
    tag: GaloisFieldElement
    original_cipher_length: int
    original_ad_length: int


def json_to_gcm_message(message_data: dict) -> GCMMessage:
    cipher_bytes = B64(message_data["ciphertext"]).block
    ad_bytes = B64(message_data["associated_data"]).block
    return GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(cipher_bytes),
        associated_data=GaloisFieldPolynomial.from_block(ad_bytes),
        tag=GaloisFieldElement.from_block_gcm(B64(message_data["tag"]).block),
        original_cipher_length=len(cipher_bytes),
        original_ad_length=len(ad_bytes)
    )


def get_zeroed_poly(message: GCMMessage) -> GaloisFieldPolynomial:
    """returns 0 = cnHn + cn−1Hn−1 + . . . + c2H2 + LH + T"""
    poly = GaloisFieldPolynomial([])

    poly.add_elements(message.tag)

    L = get_l(message.original_ad_length, message.original_cipher_length)
    poly.add_elements(L)

    for i in range(len(message.ciphertext) - 1, -1, -1):
        poly.add_elements(message.ciphertext[i])

    for i in range(len(message.associated_data) - 1, -1, -1):
        poly.add_elements(message.associated_data[i])

    return poly


def gcm_crack(nonce: bytes, m1: GCMMessage, m2: GCMMessage, m3: GCMMessage, forgery_ciphertext: bytes,
              forgery_ad: bytes):
    Tu = get_zeroed_poly(m1)
    Tv = get_zeroed_poly(m2)

    F = Tu - Tv
    F.make_monic()

    roots = find_roots(F)
    h_candidates = [root[0] for root in roots]

    correct_auth_key = None
    for potential_auth_key in h_candidates:
        # Calculate back the ek0 for the given auth key, stays the same due to same nonce etc.
        m1_l = get_l(m1.original_ad_length, m1.original_cipher_length)
        m1_ghash = get_ghash(potential_auth_key, m1.associated_data, m1.ciphertext, m1_l)
        ek0 = m1_ghash + m1.tag

        # Try to authenticate m3 with potential auth key (check if real tag is the same
        m3_l = get_l(m3.original_ad_length, m3.original_cipher_length)
        m3_ghash = get_ghash(potential_auth_key, m3.associated_data, m3.ciphertext, m3_l)
        tag = ek0 + m3_ghash

        if tag == m3.tag:
            correct_auth_key = potential_auth_key
            break

    assert correct_auth_key is not None, "No Correct auth Key has been found"

    print(correct_auth_key.to_b64_gcm())
