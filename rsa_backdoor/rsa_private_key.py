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
    d = int(decoded['privateExponent'])

    print(d)



b64_der = """MIICXAIBAAKBgQDerb7vzAD/7icmAUKB1ufxU7rSB1KCvFJbYI4
MfgMGIS7y1Ju/EOJ0snGit9FSsiskHIU0E8Co28mvpV69qwo5fdiOaL/c1oL
p/ANVk+qmaOTKL/xRIUkXfh6X1LwfljejHxKw8N977rZ/ChT4srM4nNFrXdV
6fAiE5NrZ+lDjfQIDAQABAoGBAIVLP+ZPGbIZnvmS+3q5Z/H/iu86TtvPWwU
z0RQNQkYjCvV06x3+P3BXeMpMelKkMErXf6zivgrWNe6ccQ/cGKuZmmFVWAI
uIsM5GTiEz0Ov7unkoqBoP0+9dUEiL6GvPataViHmiNscLf2JotD00hFqDZ2
6RINmBeWYazwZr0fBAkEAwodaEDHYM+Liw11EBsEUNBDc5wUAMDylJRdN0Co
JEWhQCl/07fJcdOAMezjzh/LPMbg9IKTAxD7dk+nEdbl0KQJBASULn0of17m
aKMo7e0rWYRmL/VdK/nBkMLHtUDUxz1GP1uX3DlxBzTu7k6vlacgGftJTsNS
YnZAaftRFWj1f/zUCQF+5r24suRG/Yot0x9bzCHgenDXq1g7mqPW5pAb9yHy
ScmDIm4TEMQ8qebnhaqXJrH/xA9Oef2WS8gKplI3B9xECQDbgy07FUc/XN8Z
Ph1JHfV2cYrAjQizoBlp7t6aOkmWSy0q7jnvmcrm58fih+MJVvRBETfwyLGe
dHp0/85tEy/UCQHSvm3HtEvR7u7FQxT3shRZYr0BbSw5mZMJAnIvjvAg6c4R
tVNOxOMimiovaL+R6BoiPAdDmGUkYWVNNAEC/9S0="""

der = B64(b64_der).block
calc_primes_from_der(der)

#93602190489914040367943268622243194346412248039216708244467648990797760571032348404471372881686670358740272786000158228022636975280017101267480631664857251168812081047235507071837011631159682542850051234534428166587779109844976410409722821077134183816129927163393004502591015311290205933011803749584328411073