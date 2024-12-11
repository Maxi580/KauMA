import time

from block_poly.b64 import B64
from block_poly.coefficients import Coefficients
from block_poly.poly import Poly


def test_performance():
    asdf = [1, 0, 3]
    start_time = time.time()
    for i in range(100000):
        asd = Coefficients.from_xex_semantic(asdf).b64
    end_time = time.time()
    print(f"Result = {end_time - start_time}")
