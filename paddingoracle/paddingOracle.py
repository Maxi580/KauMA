from block_poly.b64_block import B64Block
from paddingoracle.client import Client
import secrets

BLOCK_SIZE = 16


def invert_second_last_byte(successful_padding_messages: list[bytes]):
    inverted_messages = []
    for successful_padding_message in successful_padding_messages:
        inverted_byte = bytes(successful_padding_message[-2] ^ 0xFF)
        inverted_messages.append(successful_padding_message[:-2] + inverted_byte + successful_padding_message[-1:])
    return inverted_messages


def get_messages_with_correct_padding(bruteforce_messages: list[bytes], server_response: bytes):
    if len(bruteforce_messages) != len(server_response):
        raise ValueError("Len of Bruteforce Messages and server response doesnt match")

    successful_padding_messages = []
    for idx, response in enumerate(server_response):
        if response == 0x01:
            successful_padding_messages.append(bruteforce_messages[idx])
    return successful_padding_messages


class PaddingOracle:
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

    def attack_block(self):
        self.client.send_ciphertext(self.ciphertext)

        for i in range(len(ciphertext), 0, -1):
            bruteforce_messages = self._generate_bruteforce_messages()

            response = self.client.send_q_blocks(bruteforce_messages)

            successful_messages = get_messages_with_correct_padding(bruteforce_messages, response)

            # In the first iteration if there are more than one correct paddings, invert second last byte
            if len(successful_messages) > 1:
                inverted_messages = invert_second_last_byte(successful_messages)
                response = self.client.send_q_blocks(inverted_messages)
                successful_messages = get_messages_with_correct_padding(inverted_messages, response)
            elif len(successful_messages) == 0:
                raise Exception("No correct Paddings found")

            successful_message = successful_messages[0]
            self.found_dc[self.position] = self._calculate_dc(successful_message)

            self._increase_padding()

            self.position -= 1

        q = iv + self.ciphertext[:len(ciphertext)]
        plaintext = bytes(x ^ y for x, y in zip(self.found_dc, q))

        self.client.close()
        return plaintext


def attack_ciphertext(ciphertext: bytes, iv: bytes, host: str, port: int):
    plaintext = bytearray()

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        current_block = ciphertext[i:i + BLOCK_SIZE]
        previous_byte = iv if i == 0 else ciphertext[i - 1]

        client = Client(host, port)
        pd = PaddingOracle(current_block, previous_byte, client)
        plaintext.extend(pd.attack_block())

    return plaintext


ciphertext = B64Block('UHiPfbICIlExsKUclM9Hxg==').block
plaintext = B64Block("VGhpcyB0aGluZyB3b3Jrcw==").block
iv = B64Block("dxTwbO/hhIeycOTbTnp8QQ==").block

print(attack_ciphertext(ciphertext, iv, 'localhost', 9999))

