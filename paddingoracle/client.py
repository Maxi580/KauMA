import socket


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def send_q_blocks(self, q_blocks: list[bytes]) -> bytes:
        length_bytes = len(q_blocks).to_bytes(2, "little")
        sent = self.socket.send(length_bytes)
        if sent != 2:
            raise RuntimeError("Failed to send length bytes")

        for q_block in q_blocks:
            self.socket.send(q_block)

        response = self.socket.recv(len(q_blocks))
        if not response:
            raise RuntimeError("Server closed connection")

        return response

    def send_ciphertext(self, ciphertext: bytes):
        self.socket.send(ciphertext)

    def close(self):
        self.socket.close()
