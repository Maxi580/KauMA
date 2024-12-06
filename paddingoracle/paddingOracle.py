from constants import BLOCK_SIZE, BRUTEFORCE_CHUNK_SIZE
from paddingoracle.client import Client
from utils import xor_bytes


def _invert_second_last_byte(successful_padding_messages: list[bytes]) -> list[bytes]:
    inverted_messages = []
    for successful_padding_message in successful_padding_messages:
        inverted_message = bytearray(successful_padding_message)
        inverted_message[-2] ^= 0xFF
        inverted_messages.append(bytes(inverted_message))
    return inverted_messages


def _get_messages_with_correct_padding(bruteforce_messages: list[bytes], server_response: bytes):
    successful_padding_messages = []
    for idx, response in enumerate(server_response):
        if response == 0x01:
            successful_padding_messages.append(bruteforce_messages[idx])
    return successful_padding_messages


class PaddingOracleBlock:
    """Logic to Recover a 16 Byte block via Padding Oracle"""
    def __init__(self, ciphertext: bytes, iv: bytes, host: str, port: int):
        self.ciphertext = ciphertext
        self.iv = iv

        self.client = Client(host, port)

        # Message that is manipulated byte by byte to achieve the desired padding
        self.crafted_message: bytearray = bytearray(BLOCK_SIZE)
        self.padding_value = 1
        self.position = BLOCK_SIZE - 1
        self.found_dc: bytearray = bytearray(BLOCK_SIZE)

    def _generate_bruteforce_messages(self) -> list[bytes]:
        bruteforce_messages = []

        for i in range(256):
            new_message = bytearray(self.crafted_message)
            new_message[self.position] = i

            bruteforce_messages.append(bytes(new_message))
        return bruteforce_messages

    def _calculate_dc(self, successful_padding_message: bytes) -> int:
        q = successful_padding_message[self.position]
        dc = self.padding_value ^ q

        return dc

    def _increase_padding(self):
        self.padding_value += 1
        for i in range(1, self.padding_value):
            self.crafted_message[-i] = self.found_dc[-i] ^ self.padding_value

    def recover_plaintext_block(self):
        self.client.send_ciphertext(self.ciphertext)

        for i in range(BLOCK_SIZE):
            bruteforce_messages = self._generate_bruteforce_messages()
            successful_messages = []

            # Get Messages that result in successful padding
            if i != 0:
                for chunk_start in range(0, len(bruteforce_messages), BRUTEFORCE_CHUNK_SIZE):
                    chunk_end = chunk_start + BRUTEFORCE_CHUNK_SIZE
                    bruteforce_chunk = bruteforce_messages[chunk_start: chunk_end]
                    response = self.client.send_q_blocks(bruteforce_chunk)
                    successful_messages = _get_messages_with_correct_padding(bruteforce_chunk, response)

            else:
                # In First Iteration there can be more than one valid padding message
                response = self.client.send_q_blocks(bruteforce_messages)
                successful_messages = _get_messages_with_correct_padding(bruteforce_messages, response)

                if len(successful_messages) > 1:
                    inverted_messages = _invert_second_last_byte(successful_messages)
                    response = self.client.send_q_blocks(inverted_messages)
                    successful_messages = _get_messages_with_correct_padding(inverted_messages, response)

            assert len(successful_messages) == 1, "More than one successful after invert message (iter 1)"
            successful_message = successful_messages[0]
            self.found_dc[self.position] = self._calculate_dc(successful_message)
            self._increase_padding()
            self.position -= 1

        self.client.close()
        plaintext = xor_bytes(self.found_dc, self.iv)
        return plaintext


def recover_padding_oracle_plaintext(ciphertext: bytes, iv: bytes, host: str, port: int):
    """Recover Plaintext, 16 byte block by 16 byte block, because server handles 16 bytes a time"""
    plaintext = bytearray()

    blocks = [iv] + [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    for i in range(1, len(blocks)):
        current_block = blocks[i]
        iv = blocks[i - 1]

        pd = PaddingOracleBlock(current_block, iv, host, port)

        plaintext_block = pd.recover_plaintext_block()
        plaintext.extend(plaintext_block)

    return bytes(plaintext)
