import socket


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))

    def _receive_exact(self, n: int) -> bytes:
        data = bytearray()
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                raise ConnectionError("Connection closed by server before receiving all data")
            data.extend(packet)
        return bytes(data)

    def send_q_blocks(self, q_blocks: list[bytes]) -> bytes:
        length_bytes = len(q_blocks).to_bytes(2, "little")
        self.socket.sendall(length_bytes)

        concatenated_blocks = b''.join(q_blocks)
        self.socket.sendall(concatenated_blocks)

        return self._receive_exact(len(q_blocks))

    def send_ciphertext(self, ciphertext: bytes):
        self.socket.sendall(ciphertext)

    def close(self):
        self.socket.close()
