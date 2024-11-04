from block_poly.b64_block import B64Block
from paddingoracle.client import Client
import secrets


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
    def __init__(self, ciphertext, client: Client):
        self.ciphertext = ciphertext

        self.client = client

        self.crafted_message: bytearray = bytearray(len(self.ciphertext))
        self.found_dc: bytearray = bytearray(len(self.ciphertext))
        self.position = len(self.ciphertext) - 1
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
        print(f"DC in in increase Padding: {self.found_dc}")
        for i in range(1, self.padding_value):
            print(f"Increased Padding: {self.padding_value}")
            self.crafted_message[-i] = self.found_dc[-i] ^ self.padding_value

    def attack_block(self):
        try:
            self.client.send_ciphertext(self.ciphertext)

            for i in range(len(ciphertext), 0, -1):
                bruteforce_messages = self._generate_bruteforce_messages()
                print(f"bruteforce messages: {bruteforce_messages}")

                response = self.client.send_q_blocks(bruteforce_messages)
                print(f"response: {response}")

                successful_messages = get_messages_with_correct_padding(bruteforce_messages, response)
                print(f"Successful messages: {successful_messages}")

                # In the first iteration if there are more than one correct paddings, invert second last byte
                if len(successful_messages) > 1:
                    inverted_messages = invert_second_last_byte(successful_messages)
                    response = self.client.send_q_blocks(inverted_messages)
                    successful_messages = get_messages_with_correct_padding(inverted_messages, response)
                elif len(successful_messages) == 0:
                    raise Exception("No correct Paddings found")

                successful_message = successful_messages[0]
                self.found_dc[self.position] = self._calculate_dc(successful_message)
                print(f"Found Dc: {self.found_dc[self.position]}")

                self._increase_padding()
                print(f"Crafted Message: {self.crafted_message}")

                self.position -= 1

            plaintext = bytes(x ^ y for x, y in zip(self.found_dc, self.ciphertext))
            print(f"Plaintext: {plaintext}")

        finally:
            print("Closing Connection")
            self.client.close()


ciphertext = B64Block('UHiPfbICIlExsKUclM9Hxg==').block
plaintext = B64Block("VGhpcyB0aGluZyB3b3Jrcw==").block
iv = B64Block("dxTwbO/hhIeycOTbTnp8QQ==").block


print(f"Plaintext: {plaintext}")

client = Client('localhost', 9999)
pd = PaddingOracle(ciphertext, client)

pd.attack_block()
