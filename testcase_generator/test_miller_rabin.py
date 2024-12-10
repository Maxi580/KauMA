import random
from cryptography.hazmat.primitives.asymmetric import rsa
from rsa_backdoor.rsa import RSA_PUBLIC_KEY
from rsa_backdoor.glasskey import is_prime
from typing import Tuple


def generate_random_primes(bit_size: int) -> Tuple[int, int]:
    """Generates random p, q primes"""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_KEY,
        key_size=bit_size
    )

    private_numbers = private_key.private_numbers()
    p = private_numbers.p
    q = private_numbers.q

    return p, q


NON_PRIMES = [
    4, 6, 8, 9, 10, 15, 16, 25, 27,
    # Carmichael numbers (these pass some primality tests)
    561, 1105, 1729, 2465, 2821, 6601, 8911,
    # Powers of primes
    128, 243, 625,
    # Products of several primes
    901, 1001,
    # Large composites
    65536,  # 2^16
    # product of two primes
    15477, 32767,
]
PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    997, 1009, 1013, 1019, 123457, 2029, 2039, 2053, 3037,
    3041, 3049, 4001, 4003, 4007, 5003, 5009, 5011, 6007,
    6011, 6029, 7001, 7013, 7019, 32771, 65537, 524287,
    6700417, 15485863,
    10188295655806144951210003726542263794721744673042476115778002398298580042407024191408143288329007309707793562071532901154618885835462358068368715080627241
]


def test_deterministic():
    # Using already defined Primes
    for prime in PRIMES:
        if is_prime(prime) is False:
            raise ValueError(f"Prime {prime} came back as False")

    for not_prime in NON_PRIMES:
        if is_prime(not_prime) is True:
            raise ValueError(f"Non Prime {not_prime} came back as True")


def test_random():
    # Using Random Primes
    for i in range(100):
        p, q = generate_random_primes(random.randint(1024, 2048))
        if is_prime(p) is False:
            raise ValueError(f"Random Generated Prime {p} came back as False")
        elif is_prime(q) is False:
            raise ValueError(f"Random Generated Prime {q} came back as False")
