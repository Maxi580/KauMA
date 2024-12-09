from pyasn1.type import namedtype, univ
from pyasn1.codec.der import encoder

RSA_PUBLIC_KEY = 65537


class RSAKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer()),
        namedtype.NamedType('modulus', univ.Integer()),
        namedtype.NamedType('publicExponent', univ.Integer()),
        namedtype.NamedType('privateExponent', univ.Integer()),
        namedtype.NamedType('prime1', univ.Integer()),
        namedtype.NamedType('prime2', univ.Integer()),
        namedtype.NamedType('exponent1', univ.Integer()),
        namedtype.NamedType('exponent2', univ.Integer()),
        namedtype.NamedType('coefficient', univ.Integer())
    )


def generate_rsa_key(p: int, q: int) -> RSAKey:
    """Calculates every rsa value from p and q"""
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(RSA_PUBLIC_KEY, -1, phi)
    exp1 = d % (p - 1)
    exp2 = d % (q - 1)
    coef = pow(q, -1, p)

    private_key = RSAKey()
    private_key['version'] = 0
    private_key['modulus'] = n
    private_key['publicExponent'] = RSA_PUBLIC_KEY
    private_key['privateExponent'] = d
    private_key['prime1'] = p
    private_key['prime2'] = q
    private_key['exponent1'] = exp1
    private_key['exponent2'] = exp2
    private_key['coefficient'] = coef

    return private_key


def rsa_key_to_bytes(rsa_key: RSAKey) -> bytes:
    return encoder.encode(rsa_key)


def decrypt_rsa(private_key: RSAKey, ciphertext: bytes) -> bytes:
    c = int.from_bytes(ciphertext, 'big')
    d = int(private_key['privateExponent'])
    n = int(private_key['modulus'])

    m = pow(c, d, n)
    return m.to_bytes((n.bit_length() + 7) // 8, 'big')

