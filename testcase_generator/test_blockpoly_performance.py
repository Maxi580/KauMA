import time

from block_poly.b64 import B64
from block_poly.poly import Poly


def test_performance():
    asdf = "ARIAAAAAAAAAAAAAAAAAgA=="
    start_time = time.time()
    for i in range(100000):
        asd = B64(asdf).gcm_coefficients
    end_time = time.time()
    print(f"Result = {end_time - start_time}")
