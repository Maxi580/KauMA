from block_poly.b64_block import B64Block
from paddingoracle.client import Client

BLOCK_SIZE = 16
BRUTEFORCE_CHUNK_SIZE = 16


def invert_second_last_byte(successful_padding_messages: list[bytes]) -> list[bytes]:
    inverted_messages = []
    for successful_padding_message in successful_padding_messages:
        inverted_message = bytearray(successful_padding_message)
        inverted_message[-2] ^= 0xFF
        inverted_messages.append(bytes(inverted_message))
    return inverted_messages


def get_messages_with_correct_padding(bruteforce_messages: list[bytes], server_response: bytes):
    successful_padding_messages = []
    for idx, response in enumerate(server_response):
        if response == 0x01:
            successful_padding_messages.append(bruteforce_messages[idx])
    return successful_padding_messages


class PaddingOracleBlock:
    def __init__(self, ciphertext: bytes, iv: bytes, client: Client):
        self.ciphertext = ciphertext
        self.iv = iv

        self.client = client

        self.crafted_message: bytearray = bytearray(BLOCK_SIZE)
        self.found_dc: bytearray = bytearray(BLOCK_SIZE)
        self.position = BLOCK_SIZE - 1
        self.padding_value = 1

    def _generate_bruteforce_messages(self) -> list[bytes]:
        bruteforce_messages = []

        for i in range(256):
            bruteforce_value = i.to_bytes(1, 'big')
            new_message = bytearray(self.crafted_message)
            new_message[self.position] = bruteforce_value[0]

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

    def get_plaintext_block(self):
        self.client.send_ciphertext(self.ciphertext)

        for i in range(BLOCK_SIZE):
            bruteforce_messages = self._generate_bruteforce_messages()

            successful_messages = []
            if i > 0:
                for chunk_start in range(0, len(bruteforce_messages), BRUTEFORCE_CHUNK_SIZE):
                    chunk_end = chunk_start + BRUTEFORCE_CHUNK_SIZE
                    bruteforce_chunk = bruteforce_messages[chunk_start: chunk_end]

                    response = self.client.send_q_blocks(bruteforce_chunk)

                    successful_messages = get_messages_with_correct_padding(bruteforce_chunk, response)
                    if len(successful_messages) > 0:
                        break

            else:
                response = self.client.send_q_blocks(bruteforce_messages)

                successful_messages = get_messages_with_correct_padding(bruteforce_messages, response)

                if len(successful_messages) > 1:
                    inverted_messages = invert_second_last_byte(successful_messages)
                    response = self.client.send_q_blocks(inverted_messages)
                    successful_messages = get_messages_with_correct_padding(inverted_messages, response)

            [successful_message] = successful_messages

            self.found_dc[self.position] = self._calculate_dc(successful_message)

            self._increase_padding()

            self.position -= 1

        plaintext = bytes(x ^ y for x, y in zip(self.found_dc, self.iv))

        self.client.close()
        return plaintext


def get_plaintext(ciphertext: bytes, iv: bytes, host: str, port: int):
    plaintext = bytearray()

    blocks = [iv] + [ciphertext[i:i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]

    for i in range(1, len(blocks)):
        current_block = blocks[i]
        iv = blocks[i - 1]

        client = Client(host, port)
        pd = PaddingOracleBlock(current_block, iv, client)

        plaintext_block = pd.get_plaintext_block()
        plaintext.extend(plaintext_block)

    return bytes(plaintext)
