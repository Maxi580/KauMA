from crypto_algorithms.gcm import get_l, get_ghash
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
from gcm_crack.find_roots import find_roots
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


def _find_correct_h(h_candidates: list[GaloisFieldElement], m1: GCMMessage, m3: GCMMessage) \
        -> tuple[GaloisFieldElement, GaloisFieldElement]:
    for potential_auth_key in h_candidates:
        # Calculate back the ek0 for the given auth key, stays the same due to same nonce etc.
        m1_l = get_l(m1.ad_bytes, m1.ciphertext_bytes)
        m1_ghash = get_ghash(potential_auth_key, m1.associated_data, m1.ciphertext, m1_l)
        ek0 = m1_ghash + m1.tag

        # Try to authenticate m3 with potential auth key
        m3_l = get_l(m3.ad_bytes, m3.ciphertext_bytes)
        m3_ghash = get_ghash(potential_auth_key, m3.associated_data, m3.ciphertext, m3_l)
        tag = ek0 + m3_ghash

        # If Tag is the same, authentication is successful
        if tag == m3.tag:
            return potential_auth_key, ek0


def gcm_crack(nonce: bytes, m1: GCMMessage, m2: GCMMessage, m3: GCMMessage, forgery: GCMForgery):
    f1 = _get_zeroed_poly(m1)
    f2 = _get_zeroed_poly(m2)

    F = f1 - f2

    assert F != GaloisFieldPolynomial([GaloisFieldElement(0)]), "M1 and m2 are equal"

    F.make_monic()

    roots = find_roots(F)
    h_candidates = [root[0] for root in roots]

    correct_h, mask = _find_correct_h(h_candidates, m1, m3)
    assert correct_h is not None, "No Correct auth Key has been found"

    forgery_l = get_l(forgery.ad_bytes, forgery.ciphertext_bytes)
    forgery_ghash = get_ghash(correct_h, forgery.associated_data, forgery.ciphertext, forgery_l)
    forgery_tag = forgery_ghash + mask

    return forgery_tag, correct_h, mask
