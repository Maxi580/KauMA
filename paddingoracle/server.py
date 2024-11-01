import socket
import secrets
from sea128 import aes_decrypt
import cryptography.hazmat.primitives.padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DEFAULT_TIMEOUT: float = 10.0


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def check_pkcs7_padding(pt):
    padder = cryptography.hazmat.primitives.padding.PKCS7(128).unpadder()
    padder.update(pt)
    try:
        padder.finalize()
    except ValueError:
        return False
    return True


class Server:
    def __init__(self, host='localhost', port=9999):
        self.block_size = 16
        self.key = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.cipher = Cipher(
            algorithms.AES(self.key),
            modes.CBC(self.iv),
            backend=default_backend()
        )
        self.ciphertext = None
        self.plaintext = None

        self.host = host
        self.port = port
        self.timeout: float = DEFAULT_TIMEOUT

    def decrypt_cbc(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()

    def handle_client(self, client_socket):
        try:
            self.ciphertext = client_socket.recv(self.block_size)
            print(f"Got Ciphertext: {self.ciphertext}")

            self.plaintext = self.decrypt_cbc(self.ciphertext)
            print(f"Plaintext: {self.plaintext}")

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
                    q = client_socket.recv(self.block_size)

                    decrypted_q = self.decrypt_cbc(q)

                    is_valid = check_pkcs7_padding(decrypted_q)

                    responses.append(b'\x01' if is_valid else b'\x00')

                print(f"Responses: {responses}\n\n")
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

        print(f"Server started on {self.host}:{self.port}")
        print(f"Using key: {self.key.hex()}")

        try:
            while True:
                try:
                    client, addr = server.accept()
                    print(f"Accepted connection from {addr}")
                    self.handle_client(client)
                    print(f"Closed connection from {addr}")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")

        except KeyboardInterrupt:
            print("\nShutting down server")
        finally:
            print("Closing server")
            server.close()


if __name__ == '__main__':
    b64_iv = "dxTwbO/hhIeycOTbTnp8QQ=="

    server = Server()
    server.run()
