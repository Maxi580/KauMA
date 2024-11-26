from block_poly.block import Block
from crypto_algorithms.gcm import gcm_encrypt, get_eky0, get_auth_key
from crypto_algorithms.sea128 import aes_encrypt, sea_encrypt
from gcm_types import GCMMessage, GCMForgery
from gcm_crack import gcm_crack
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
import random
import secrets


def randomize_test_data(encryption_algorithm, reused_nonce, key):
    plaintext_len = random.randint(1, 16)
    plaintext = secrets.token_bytes(plaintext_len)
    ad_len = random.randint(1, 16)
    ad = secrets.token_bytes(ad_len)
    ciphertext, tag, _, _ = gcm_encrypt(encryption_algorithm, reused_nonce, key, plaintext, ad)

    return ciphertext, ad, tag


if __name__ == '__main__':
    reused_nonce = secrets.token_bytes(12)
    key = secrets.token_bytes(16)
    encryption_algorithm = aes_encrypt

    ciphertext, ad, tag = randomize_test_data(encryption_algorithm, reused_nonce, key)
    print(f"m1: ciphertext: {Block(ciphertext).b64} ad: {Block(ad).b64} tag: {Block(tag).b64}")
    m1 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    ciphertext, ad, tag = randomize_test_data(encryption_algorithm, reused_nonce, key)
    print(f"m2: ciphertext: {Block(ciphertext).b64} ad: {Block(ad).b64} tag: {Block(tag).b64}")
    m2 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    ciphertext, ad, tag = randomize_test_data(encryption_algorithm, reused_nonce, key)
    print(f"m3: ciphertext: {Block(ciphertext).b64} ad: {Block(ad).b64} tag: {Block(tag).b64}")
    m3 = GCMMessage(
        ciphertext=GaloisFieldPolynomial.from_block(ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(ad),
        tag=GaloisFieldElement.from_block_gcm(tag),
        ciphertext_bytes=ciphertext,
        ad_bytes=ad
    )

    forgery_ciphertext, forgery_ad, forgery_tag = randomize_test_data(encryption_algorithm, reused_nonce, key)
    print(
        f"forgery: ciphertext: {Block(forgery_ciphertext).b64} ad: {Block(forgery_ad).b64} tag: {Block(forgery_tag).b64}")
    forgery = GCMForgery(
        ciphertext=GaloisFieldPolynomial.from_block(forgery_ciphertext),
        associated_data=GaloisFieldPolynomial.from_block(forgery_ad),
        ciphertext_bytes=forgery_ciphertext,
        ad_bytes=forgery_ad
    )

    cracked_tag, cracked_H, cracked_mask = gcm_crack(reused_nonce, m1, m2, m3, forgery)

    print(f"cracked_tag: {cracked_tag.to_b64_gcm()}")
    print(f"Correct tag: {Block(forgery_tag).b64}")
    print("\n")
    print(f"cracked_H: {cracked_H.to_b64_gcm()}")
    print(f"Correct H: {get_auth_key(key, encryption_algorithm).to_b64_gcm()}")
    print("\n")
    print(f"cracked_mask: {cracked_mask.to_b64_gcm()}")
    print(f"Correct mask: {get_eky0(key, reused_nonce, encryption_algorithm).to_b64_gcm()}")
