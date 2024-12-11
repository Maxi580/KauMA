import time
from block_poly.poly import Poly


def test_performance():
    fixed_poly = 4000
    start_time = time.time()
    for i in range(1000000):
        p = Poly.from_xex_semantic(fixed_poly)
        calc = p.b64
    end_time = time.time()
    print(f"Result = {end_time - start_time}")
