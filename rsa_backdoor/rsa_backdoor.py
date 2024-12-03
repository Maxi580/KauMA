import hashlib
import hmac
import math


class Glasskey:
    def __init__(self, agency_key: bytes, seed: bytes):
        self.agency_key = agency_key
        self.seed = seed

    def _prng_block(self, i: int) -> bytes:
        i_bytes = int.to_bytes(i, 8, byteorder='little')

        k_hash = hashlib.sha256(self.agency_key).digest()
        s_hash = hashlib.sha256(self.seed).digest()
        k_star = k_hash + s_hash

        return hmac.new(k_star, i_bytes, hashlib.sha256).digest()

    def prng(self, lengths: list[int]) -> list[bytes]:
        """ 1. Generate 32 Byte Block
            2. Extract request Byte length from block, increase position
            3. If original Block is exhausted generate new one
            4. Continue until every length block is satisfied"""

        results = []
        current_pos = 0
        current_block = None
        i = 0

        for length in lengths:
            output = bytearray()
            bytes_needed = length

            while bytes_needed > 0:
                if current_block is None or current_pos >= len(current_block):
                    current_block = self._prng_block(i)
                    current_pos = 0
                    i += 1

                bytes_to_take = min(bytes_needed, len(current_block) - current_pos)
                output.extend(current_block[current_pos:current_pos + bytes_to_take])

                current_pos += bytes_to_take
                bytes_needed -= bytes_to_take

            results.append(output)
        return results

    def int_bits(self, b_list: list[int]) -> list[int]:
        """Extracts the b lowest bits from data generated from b_list"""
        lengths = [math.ceil(b / 8) for b in b_list]
        s = self.prng(lengths)

        assert len(b_list) == len(s), "len of b_list and s/lengths is not equal"

        results = []
        for i in range(len(s)):
            s_star = int.from_bytes(s[i], byteorder='little')
            mask = (1 << b_list[i]) - 1
            results.append(s_star & mask)

        return results
