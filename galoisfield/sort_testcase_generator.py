import uuid
from utils import save_test_cases
from galoisfield.galoisfieldelement import GaloisFieldElement
from galoisfield.galoisfieldpolynomial import GaloisFieldPolynomial
import random


def generate_test_case():
    test_uuid = str(uuid.uuid4())
    test_name = f"gfpoly-sort-{test_uuid}"

    polys = []
    poly_cnt = 20
    max_degree = 10

    max_value = (1 << 128) - 1

    for _ in range(poly_cnt):
        degree = random.randint(0, max_degree)

        coeffs = []
        for _ in range(degree + 1):
            value = random.randint(0, max_value)
            coeffs.append(GaloisFieldElement(value))

        poly = GaloisFieldPolynomial(coeffs)
        poly.remove_leading_zero()
        polys.append(poly)

    sorted_polys = sorted(polys, key=lambda p: (
        p.degree,  # First sort by degree
        [int(coeff) for coeff in reversed(p._gfe_list)]  # Then by coefficients from highest to lowest
    ))

    input_polys = polys.copy()
    random.shuffle(input_polys)

    input_case = {
        test_name: {
            "action": "gfpoly_sort",
            "arguments": {
                "polys": [poly.to_b64() for poly in input_polys]
            }
        }
    }

    expected_case = {
        test_name: {
            "sorted_polys": [poly.to_b64() for poly in sorted_polys]
        }
    }

    return input_case, expected_case


if __name__ == '__main__':
    all_input_cases = {}
    all_expected_outputs = {}

    for i in range(50):
        input_case, expected_output = generate_test_case()
        all_input_cases.update(input_case)
        all_expected_outputs.update(expected_output)

    save_test_cases(all_input_cases, all_expected_outputs)
