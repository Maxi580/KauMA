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

    return p, q


der = """MIICXAIBAAKBgQDerb7vzAD/7icmAUKB1ufxU7rSB1KCvFJbYI4
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

p, q = calc_primes_from_der(B64(der).block)

print(f"p: {p}, q: {q}")

#p: 10188295655806144951210003726542263794721744673042476115778002398298580042407024191408143288329007309707793562071532901154618885835462358068368715080627241,
# q: 15348032924910726575401082387888061390701933922885044002520172519647433813021658010692575298102345359448181797463196851425928145233165383786364468629339957
