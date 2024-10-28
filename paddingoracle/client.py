import socket
from block_poly.b64_block import B64Block


class Client:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.sock = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.hostname, self.port))

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def send_data(self, data):
        pass
