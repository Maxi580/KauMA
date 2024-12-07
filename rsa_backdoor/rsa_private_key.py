from pyasn1.type import namedtype, univ
from pyasn1.codec.der import encoder, decoder
from block_poly.b64 import B64


class RSAPrivateKey(univ.Sequence):
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


def generate_rsa_key_from_primes(p: int, q: int, e: int = 65537) -> bytes:
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    exp1 = d % (p - 1)
    exp2 = d % (q - 1)
    coef = pow(q, -1, p)

    private_key = RSAPrivateKey()
    private_key['version'] = 0
    private_key['modulus'] = n
    private_key['publicExponent'] = e
    private_key['privateExponent'] = d
    private_key['prime1'] = p
    private_key['prime2'] = q
    private_key['exponent1'] = exp1
    private_key['exponent2'] = exp2
    private_key['coefficient'] = coef

    return encoder.encode(private_key)


def calc_primes_from_der(der: bytes):
    decoded, _ = decoder.decode(der, asn1Spec=RSAPrivateKey())

    p = int(decoded['prime1'])
    q = int(decoded['prime2'])
