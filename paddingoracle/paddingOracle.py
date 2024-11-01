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

        self.len_ciphertext = len(self.ciphertext)

        self.client = client

        self.crafted_message: bytearray = bytearray(self.len_ciphertext)
        self.calculated_dc: bytearray = bytearray(self.len_ciphertext)
        self.position = self.len_ciphertext - 1
        self.padding_value = (self.len_ciphertext - self.position).to_bytes(1, "big")

    def generate_bruteforce_messages(self) -> list[bytes]:
        bruteforce_messages = []

        for i in range(256):
            bruteforce_value = i.to_bytes(1)
            new_message = bytearray(self.crafted_message)
            new_message[self.position] = bruteforce_value[0]

            if len(new_message) != self.len_ciphertext:
                raise ValueError(f"{new_message} is not {self.len_ciphertext} Bytes")

            bruteforce_messages.append(bytes(new_message))
        return bruteforce_messages

    def calculate_plaintext(self, successful_padding_message: bytes) -> bytes:
        print("\n\n Calculating Plaintext...")

        print(f"Successful Padding Message: {successful_padding_message}")

        q = successful_padding_message[self.position].to_bytes(1, 'big')

        print(f"Q: {q}")

        print(f"Padding Value: {self.padding_value}")

        dc = bytes(a ^ b for a, b in zip(self.padding_value, q))

        print(f"DC: {dc}")

        original_iv = self.ciphertext[self.position - 1].to_bytes(1, 'big')

        print(f"Original IV: {original_iv}")

        print(f"Result {bytes(a ^ b for a, b in zip(dc, original_iv))}")

        return bytes(a ^ b for a, b in zip(dc, original_iv))

    def prepare_next_round(self, successful_message):
        """Increases Padding by 1, position goes left"""
        self.padding_value = (int.from_bytes(self.padding_value) + 1).to_bytes(1, 'big')

        c = successful_message[self.position].to_bytes(1, 'big')
        dc = bytes(a ^ b for a, b in zip(self.padding_value, c))
        self.calculated_dc[self.position] = dc[0]

        for pos in range(self.position, self.len_ciphertext):
            dc = self.calculated_dc[pos].to_bytes(1, 'big')
            new_c = bytes(a ^ b for a, b in zip(self.padding_value, dc))
            self.crafted_message[pos] = new_c[0]

        self.position -= 1

    def attack_block(self):
        try:
            self.client.send_ciphertext(self.ciphertext)

            for i in range(1, len(ciphertext) + 1):
                bruteforce_messages = self.generate_bruteforce_messages()
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
                plaintext_byte = self.calculate_plaintext(successful_message)
                print(f"Plaintext Byte: {plaintext_byte}")
                self.prepare_next_round(successful_message)
        finally:
            print("Closing Connection")
            self.client.close()


ciphertext = b'V\x0c\x91\x1f\xa8\xcf\xd3\xfa\xc3\xbbM\x9f\x97\xd04d'

client = Client('localhost', 9999)
pd = PaddingOracle(ciphertext, client)

pd.attack_block()
