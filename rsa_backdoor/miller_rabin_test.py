from rsa_backdoor.miller_rabin import is_prime

NON_PRIMES = [
    4, 6, 8, 9, 10, 15, 16, 25, 27,
    # Carmichael numbers (these pass some primality tests)
    561,
    1105,
    1729,
    2465,
    2821,
    6601,
    8911,
    # Powers of primes
    128,    # 2^7
    243,    # 3^5
    625,    # 5^4
    # Products of several primes
    901,    # 17 * 53
    1001,   # 7 * 11 * 13
    # Large composites
    65536,  # 2^16
    # Semi-primes (product of two primes)
    15477, # 89 * 173
    32767,  # 2^15 - 1 = 7 * 73 * 127
]
PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
    997, 1009, 1013, 1019, 123457, 2029, 2039, 2053, 3037,
    3041, 3049, 4001, 4003, 4007, 5003, 5009, 5011, 6007,
    6011, 6029, 7001, 7013, 7019, 32771, 65537, 524287,
    6700417, 15485863,
    10188295655806144951210003726542263794721744673042476115778002398298580042407024191408143288329007309707793562071532901154618885835462358068368715080627241
]

for i in range(1000):
    for prime in PRIMES:
        if is_prime(prime) is False:
            raise ValueError(f"Prime {prime} came back as False")

    for not_prime in NON_PRIMES:
        if is_prime(not_prime) is True:
            raise ValueError(f"Non Prime {not_prime} came back as True")

print(f"{len(NON_PRIMES) + len(PRIMES)} tests successfully passed!")