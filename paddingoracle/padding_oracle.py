from block_poly.b64_block import B64Block


class PaddingOracle:
    def __init__(self, ciphertext: bytes):
        self.ciphertext = ciphertext
        self.crafted_message = 16 * "00"

    def bruteforce_message(self, position: int) -> list[bytes]:
        bruteforce_messages = []
        for i in range(256):
            bruteforce_value = hex(i)[2:].zfill(2)
            new_message = self.crafted_message[:position - 1] + bruteforce_value + self.crafted_message[position + 1:]
            bruteforce_messages.append(bytes(new_message, 'utf-8'))
        return bruteforce_messages

    def get_messages_with_correct_padding(self, bruteforce_messages: list[bytes], server_response: bytes):
        successful_padding_messages = []
        for response in server_response:
            if response == 1:
                successful_padding_messages.append(bruteforce_messages[0])
            bruteforce_messages.pop(0)
        return successful_padding_messages

    def get_current_padding(self, successful_padding_messages: bytes):
        if len(successful_padding_messages) == 1:


    def calculate_plaintext(self, correct_padding: bytes, q: bytes, original_iv: bytes) -> bytes:
        dc = bytes(a ^ b for a, b in zip(correct_padding, q))

        plaintext = bytes(a ^ b for a, b in zip(dc, original_iv))

        return plaintext

    def get_padding_q(self, targeted_padding: bytes, dc: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(targeted_padding, dc))



ciphertext = B64Block("e+Sn+nG28niB8Df++hmjFRTcti07wHsrivmoxnDDBaELOfLS16p/pqvAuz01UPq7").get_block()

pd = PaddingOracle(ciphertext)
"""zeros = 16 * "00"
position = 31
bruteforce_message = pd.bruteforce_message(position)
for message in bruteforce_message:
    print(len(message))
    print(bruteforce_message)"""

"""bruteforce_messages = [b'00000000000000000000000000000000', b'00000000000000000000000000000001',
                       b'00000000000000000000000000000002']
server_responses = b'\x01\x00\x00'

successful_messages = pd.get_messages_with_correct_padding(bruteforce_messages, server_responses)
print(successful_messages)"""


targeted_padding = bytes.fromhex('21')
dc = bytes.fromhex('02')

new_q = pd.get_padding_q(targeted_padding, dc)
print(bytes.hex(new_q))