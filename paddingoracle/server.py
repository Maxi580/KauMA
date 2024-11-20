import socket
import cryptography.hazmat.primitives.padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from constants import BLOCK_SIZE, DEFAULT_TIMEOUT
from utils import xor_bytes


def check_pkcs7_padding(pt):
    padder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
    padder.update(pt)
    try:
        padder.finalize()
    except ValueError:
        return False
    return True


class Server:
    def __init__(self, host, port, key):
        self.key = key
        self.cipher = Cipher(
            algorithms.AES(self.key),
            modes.ECB(),
            backend=default_backend()
        )

        self.ciphertext = None
        self.plaintext = None

        self.host = host
        self.port = port
        self.timeout: float = DEFAULT_TIMEOUT

    def _decrypt_ecb(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def _handle_client(self, client_socket):
        try:
            self.ciphertext = client_socket.recv(BLOCK_SIZE)
            self.plaintext = self._decrypt_ecb(self.ciphertext)

            while True:
                length_bytes = client_socket.recv(2)
                if len(length_bytes) != 2:
                    return

                length = int.from_bytes(length_bytes, byteorder='little')
                if length == 0:
                    return

                if length > 256:
                    return

                responses = []
                for _ in range(length):
                    q = client_socket.recv(BLOCK_SIZE)

                    plaintext_xor = xor_bytes(q, self.plaintext)

                    is_valid = check_pkcs7_padding(plaintext_xor)

                    responses.append(b'\x01' if is_valid else b'\x00')

                client_socket.sendall(b''.join(responses))

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def run(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.settimeout(self.timeout)
        server.bind((self.host, self.port))
        server.listen(1)

        try:
            while True:
                try:
                    client, addr = server.accept()
                    self._handle_client(client)

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")

        except KeyboardInterrupt:
            print("\nShutting down server")
        finally:
            server.close()
