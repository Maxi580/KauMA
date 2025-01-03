from dataclasses import dataclass
from typing import Optional

from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from block_poly.b64 import B64


@dataclass
class GCMMessage:
    ciphertext: GaloisFieldPolynomial
    associated_data: GaloisFieldPolynomial
    tag: Optional[GaloisFieldElement]
    ciphertext_bytes: bytes
    ad_bytes: bytes


def json_to_gcm_message(message_data: dict) -> GCMMessage:
    cipher_bytes = B64(message_data["ciphertext"]).block
    ad_bytes = B64(message_data["associated_data"]).block
    return GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(cipher_bytes),
        associated_data=GaloisFieldPolynomial.from_block(ad_bytes),
        tag=GaloisFieldElement.from_block_gcm(B64(message_data["tag"]).block),
        ciphertext_bytes=cipher_bytes,
        ad_bytes=ad_bytes
    )


def json_forgery_to_gcm_message(message_data: dict) -> GCMMessage:
    cipher_bytes = B64(message_data["ciphertext"]).block
    ad_bytes = B64(message_data["associated_data"]).block
    return GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(cipher_bytes),
        associated_data=GaloisFieldPolynomial.from_block(ad_bytes),
        tag=None,
        ciphertext_bytes=cipher_bytes,
        ad_bytes=ad_bytes
    )
