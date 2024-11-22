from dataclasses import dataclass

from block_poly.b64_block import B64Block
from galoisfield.galoisfieldelement import GaloisFieldElement
from gcm_crack.sff import sff
from gcm_crack.ddf import ddf
from gcm_crack.edf import edf
from crypto_algorithms.gcm import get_l
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from constants import BLOCK_SIZE


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


def get_ghash_poly(message: GCMMessage) -> GaloisFieldPolynomial:
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
    Tu = get_ghash_poly(m1)
    Tv = get_ghash_poly(m2)

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

    for factor in roots:
        print(f"Complete Result {factor.to_b64_gcm()}")


