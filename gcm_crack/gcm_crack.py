from dataclasses import dataclass

from block_poly.b64_block import B64Block
from block_poly.block import Block
from galoisfield.galoisfieldelement import GaloisFieldElement
from gcm_crack.sff import sff
from crypto_algorithms.gcm import get_l
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


def get_ghash_poly(message: GCMMessage) -> GaloisFieldPolynomial:
    poly = GaloisFieldPolynomial([])

    # Ek(Y0) cancels out, but to zero the equation we bring tag on the other side.
    poly.add_elements(GaloisFieldElement.from_block_gcm(message.tag))

    L = get_l(message.associated_data, message.ciphertext)
    poly.add_elements(GaloisFieldElement.from_block_gcm(L))

    print(f"Ciphertext len: {len(message.ciphertext)}")
    for i in range(0, len(message.ciphertext), BLOCK_SIZE):
        print(f"I Range: {i, i + BLOCK_SIZE}, Block: {Block(message.ciphertext[i: i + BLOCK_SIZE]).b64_block}, block len:"
            f"{len(message.ciphertext[i: i + BLOCK_SIZE])}")
        poly.add_elements(GaloisFieldElement.from_block_gcm(message.ciphertext[i: i + BLOCK_SIZE]))

    poly.add_elements(GaloisFieldElement.from_block_gcm(message.associated_data))

    return poly


def gcm_crack(nonce: bytes, m1: GCMMessage, m2: GCMMessage, m3: GCMMessage, forgery_ciphertext: bytes,
              forgery_ad: bytes):

    print(m1)
    print(m2)

    Tu = get_ghash_poly(m1)
    Tv = get_ghash_poly(m2)

    F = Tu - Tv

    print(f"F: {F.to_b64_gcm()}")

    F.make_monic()
    z = sff(F)

    print({"factors": [{"factor": z[i][0].to_b64_gcm(), "exponent": z[i][1]} for i in range(len(z))]})
