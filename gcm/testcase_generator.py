from crypto_algorithms.gcm import gcm_encrypt, gcm_decrypt
from crypto_algorithms.sea128 import aes_encrypt, sea_decrypt
from gcm.gcm_crack import gcm_crack
import secrets

if __name__ == '__main__':
    plaintext = b'Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.'
    ad = b''
    nonce = secrets.token_bytes(8)
    key = secrets.token_bytes(16)
    encryption_algorithm = aes_encrypt

    ciphertext = gcm_encrypt(aes_encrypt, nonce, key, plaintext, ad)

