from crypto_algorithms.gcm import get_l, get_ghash
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from gcm_crack.recover_h import recover_h

from gcm_crack.gcm_types import GCMMessage, GCMForgery


def _get_zeroed_poly(message: GCMMessage) -> GaloisFieldPolynomial:
    """returns 0 = cnHn + cn−1Hn−1 + . . . + c2H2 + LH + T"""
    poly = GaloisFieldPolynomial([])

    poly.add_elements(message.tag)

    L = get_l(message.ad_bytes, message.ciphertext_bytes)
    poly.add_elements(L)

    for i in range(len(message.ciphertext) - 1, -1, -1):
        poly.add_elements(message.ciphertext[i])

    for i in range(len(message.associated_data) - 1, -1, -1):
        poly.add_elements(message.associated_data[i])

    return poly


def gcm_crack(nonce: bytes, m1: GCMMessage, m2: GCMMessage, m3: GCMMessage, forgery: GCMForgery):
    f1 = _get_zeroed_poly(m1)
    f2 = _get_zeroed_poly(m2)

    F = f1 - f2
    F.make_monic()

    correct_h, mask = recover_h(F, m1, m3)

    forgery_l = get_l(forgery.ad_bytes, forgery.ciphertext_bytes)
    forgery_ghash = get_ghash(correct_h, forgery.associated_data, forgery.ciphertext, forgery_l)
    forgery_tag = forgery_ghash + mask

    return forgery_tag, correct_h, mask
