import hashlib
import hmac
import math
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.x509 import load_der_x509_certificate
from asn1crypto import cms

from block_poly.b64 import B64

NUMBER_OF_MR_ROUNDS = 20


def is_prime(n: int) -> bool:
    """Performs a Miller Rabin Test"""
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(NUMBER_OF_MR_ROUNDS):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


class Glasskey:
    def __init__(self, agency_key: bytes, seed: bytes):
        self.agency_key = agency_key
        self.seed = seed

        self.prng_position = 0
        self.prng_block = None
        self.prng_i = 0

    def _generate_new_prng_block(self, i: int) -> bytes:
        i_bytes = int.to_bytes(i, 8, byteorder='little')

        k_hash = hashlib.sha256(self.agency_key).digest()
        s_hash = hashlib.sha256(self.seed).digest()
        k_star = k_hash + s_hash

        return hmac.new(k_star, i_bytes, hashlib.sha256).digest()

    def prng(self, bytes_needed: int) -> bytes:
        """ 1. Generate 32 Byte Block
            2. Extract request Byte length from block, increase position
            3. If original Block is exhausted generate new one
            4. Continue until length bytes are provided."""
        result = bytearray()

        while bytes_needed > 0:
            if self.prng_block is None or self.prng_position >= len(self.prng_block):
                self.prng_block = self._generate_new_prng_block(self.prng_i)
                self.prng_position = 0
                self.prng_i += 1

            bytes_to_take = min(bytes_needed, len(self.prng_block) - self.prng_position)
            result.extend(self.prng_block[self.prng_position:self.prng_position + bytes_to_take])

            self.prng_position += bytes_to_take
            bytes_needed -= bytes_to_take

        return result

    def prng_int_bits(self, b: int) -> int:
        """Extracts the b lowest bits from data stream"""
        length = math.ceil(b / 8)
        s = self.prng(length)
        s_star = int.from_bytes(s, byteorder='little')
        mask = (1 << b) - 1
        return s_star & mask

    def prng_int_min_max(self, m: int, M: int) -> int:
        assert m <= M, "min is bigger than Max"
        s = M - m + 1
        assert s >= 0, "s must be positive"
        b = s.bit_length()

        while True:
            r = self.prng_int_bits(b)
            if r < s:
                return r + m

    def genkey(self, l: int):
        lp = l // 2
        p = self.prng_int_bits(lp)
        p |= 1 | 3 << (lp - 2)  # LSB | 2 MSB
        while not is_prime(p):
            p += 2

        r = 1 << (l - 64)
        nl = int.from_bytes(self.seed, "big") * r
        nh = nl + (r - 1)
        assert nl < nh, "nl is bigger than nh"
        ql = (nl // p) + 1
        qh = nh // p
        assert ql <= qh, "ql is bigger than qh"

        q = self.prng_int_min_max(ql, qh)
        q |= 1  # LSB
        while not is_prime(q):
            q += 2

        return p, q


def glasskey_break(cert_der: bytes, agency_key: bytes, msg: bytes):
    cert = load_der_x509_certificate(cert_der)

    public_key = cert.public_key()
    public_numbers = public_key.public_numbers()
    n = public_numbers.n

    # topmost 64 bit of modulo are seed
    seed = n >> (n.bit_length() - 64)
    assert seed.bit_length() == 64, "seed length is wrong"

    # Now we can calculate private key, because its deterministic
    gk = Glasskey(agency_key, seed.to_bytes(8, byteorder='big'))
    p, q = gk.genkey(1024)

    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    print(f"private key: {d}")

    private_numbers = rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=d % (p - 1),
        dmq1=d % (q - 1),
        iqmp=pow(q, -1, p),
        public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
    )
    private_key = private_numbers.private_key()

    # Parse CMS message
    content_info = cms.ContentInfo.load(msg)
    enveloped_data = content_info['content']

    # Get the encrypted content encryption key
    recipient_info = enveloped_data['recipient_infos'][0]  # This is a RecipientInfo object
    # Access the encrypted_key through the proper attribute
    encrypted_key = recipient_info.encrypted_key

    # Get the encrypted content and algorithm
    encrypted_content_info = enveloped_data['encrypted_content_info']
    algorithm = encrypted_content_info['content_encryption_algorithm']
    encrypted_content = encrypted_content_info['encrypted_content'].native

    # Create cipher based on algorithm and decrypt
    cipher = Cipher(
        algorithms.AES(decrypted_key),
        modes.CBC(algorithm['parameters'].native)
    )
    decryptor = cipher.decryptor()
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Remove PKCS7 padding
    padding_length = decrypted_content[-1]
    content = decrypted_content[:-padding_length]

    return content



cert_b64 = "MIICGDCCAYGgAwIBAgIUXJpxiVXlkxEenX2rjEwbsHGv8DcwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAwwTQmFja2Rvb3JlZCBHbGFzc2tleTAeFw0yNDEyMDIxODU3MTNaFw0yNTAxMDExODU3MTNaMB4xHDAaBgNVBAMTE0JhY2tkb29yZWQgR2xhc3NrZXkwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN6tvu/MAP/uJyYBQoHW5/FTutIHUoK8Ultgjgx+AwYhLvLUm78Q4nSycaK30VKyKyQchTQTwKjbya+lXr2rCjl92I5ov9zWgun8A1WT6qZo5Mov/FEhSRd+HpfUvB+WN6MfErDw33vutn8KFPiyszic0Wtd1Xp8CITk2tn6UON9AgMBAAGjUzBRMB0GA1UdDgQWBBTL5u3Jeoj2RjQP57PdTR8Twt+kTzAfBgNVHSMEGDAWgBTL5u3Jeoj2RjQP57PdTR8Twt+kTzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAJxUCHVwawZotoi8/qhFTBNz0iD3DwkYN6SFDaQbgQXtLfi8JgVM44IYRTtNtC1uD9KYOhGzal3C7+Xk1qVukzHDM1xeZ0idxwbvnv/dyDSYGoqpcedfy8zGU/xG1QDcCeKjzePV7Y6eZufnFGVsN0zUu5cRFNnFyNKa+HKalQcW"
cms_b64 = "MIIBJwYJKoZIhvcNAQcDoIIBGDCCARQCAQAxgdAwgc0CAQAwNjAeMRwwGgYDVQQDDBNCYWNrZG9vcmVkIEdsYXNza2V5AhRcmnGJVeWTER6dfauMTBuwca/wNzANBgkqhkiG9w0BAQEFAASBgIWOQpYga5Ixa0s74wtDZQtrtjQCEm/kxnPHhkHZf4Sl627pPe8dtzxh8B4qC7Fmu73UugMDS0lbbeWABt7Wu2fOnf2fXRXBFfYiJfmVM4bBBLW9gcPzjNsswTfw48dQzw+L1oi/+PZmCxUQ7NztkAhPWawj/iFRxRrAtmhDNLZVMDwGCSqGSIb3DQEHATAdBglghkgBZQMEAQIEEGasAhJ6oXdmSsElQV3686qAECE9U0KMqoujqKLgHQapxZc="
agency_key_b64 = "T01HV1RG"

cert = B64(cert_b64).block
cms_message = B64(cms_b64).block
agency_key = B64(agency_key_b64).block

glasskey_break(cert, agency_key, cms_message)

