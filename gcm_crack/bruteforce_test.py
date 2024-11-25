from block_poly.b64 import B64

if __name__ == '__main__':
    ciphertext = B64("QUQtRGF0ZW4=").block
    print(ciphertext)
