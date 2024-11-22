from dataclasses import dataclass

from block_poly.b64_block import B64Block
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement
from gcm_crack.sff import sff
from gcm_crack.ddf import ddf
from gcm_crack.edf import edf
from crypto_algorithms.gcm import get_l, get_ghash, get_auth_tag
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from constants import BLOCK_SIZE
from utils import xor_bytes


@dataclass
class GCMMessage:
    ciphertext: bytes
    associated_data: bytes
    tag: bytes


def json_to_gcm_message(message_data: dict) -> GCMMessage:
    return GCMMessage(
        ciphertext=B64Block(message_data["ciphertext"]).block,
        associated_data=B64Block(message_data["associated_data"]).block,
        tag=B64Block(message_data["tag"]).block
    )


def get_zeroed_poly(message: GCMMessage) -> GaloisFieldPolynomial:
    """returns 0 = cnHn + cn−1Hn−1 + . . . + c2H2 + LH + T"""
    poly = GaloisFieldPolynomial([])

    # Ek(Y0) cancels out, but to zero the equation we bring tag on the other side.
    poly.add_elements(GaloisFieldElement.from_block_gcm(message.tag))

    L = get_l(message.associated_data, message.ciphertext)
    poly.add_elements(GaloisFieldElement.from_block_gcm(L))

    ciphertext_elements = []
    for i in range(0, len(message.ciphertext), BLOCK_SIZE):
        ciphertext_elements.append(GaloisFieldElement.from_block_gcm(message.ciphertext[i: i + BLOCK_SIZE]))
    ciphertext_elements.reverse()  # c1 * Hn + c2 * H(n-1)....
    poly.add_elements(ciphertext_elements)

    poly.add_elements(GaloisFieldElement.from_block_gcm(message.associated_data))

    return poly


def gcm_crack(nonce: bytes, m1: GCMMessage, m2: GCMMessage, m3: GCMMessage, forgery_ciphertext: bytes,
              forgery_ad: bytes):
    Tu = get_zeroed_poly(m1)
    Tv = get_zeroed_poly(m2)

    F = Tu - Tv
    F.make_monic()

    roots = []
    for factor_sff in sff(F):
        f = factor_sff[0]

        for factor_ddf in ddf(f):
            f_ddf = factor_ddf[0]
            degree = factor_ddf[1]

            if degree == f_ddf.degree:
                roots.append(f_ddf)
            else:
                roots.extend(edf(f_ddf, degree))

    h_candidates = [root[0] for root in roots]

    for auth_key in h_candidates:
        m1_l = get_l(m1.associated_data, m1.ciphertext)
        m1_ghash = get_ghash(m1.associated_data, m1.ciphertext, auth_key.to_block_gcm(), m1_l)

        ek0 = xor_bytes(m1_ghash, m1.tag)
        print(f"ek0: {ek0}")

        m3_l = get_l(m3.associated_data, m3.ciphertext)
        m3_ghash = get_ghash(m3.associated_data, m3.ciphertext, auth_key.to_block_gcm(), m3_l)

        tag = get_auth_tag(ek0, m3_ghash)
        print(f"Tag: {Block(tag).b64_block}")
