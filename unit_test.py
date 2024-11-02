from block_poly.block import Block
from block_poly.xex_coefficients import XEX_Coefficients
from block_poly.xex_poly import XEX_Poly
from block_poly.gcm_coefficients import GCM_Coefficients
from block_poly.gcm_poly import GCM_Poly

from block_poly.b64_block import B64Block

from gfmul import xex_gfmul
from sea128 import sea_encrypt, sea_decrypt, aes_encrypt, aes_decrypt
from xex import encrypt_xex, decrypt_xex
from gcm import gcm_encrypt, gcm_decrypt, apply_key_stream


def test_poly_2_block():
    coefficients = [12, 127, 9, 0]
    result = XEX_Coefficients(coefficients)
    assert result.b64_block == "ARIAAAAAAAAAAAAAAAAAgA=="


def test_block_2_poly():
    b64_block = "ARIAAAAAAAAAAAAAAAAAgA=="
    result = B64Block(b64_block)
    assert result.xex_coefficients == [0, 9, 12, 127]


def test_gfmul():
    a = "ARIAAAAAAAAAAAAAAAAAgA=="
    b = "AgAAAAAAAAAAAAAAAAAAAA=="

    a_poly = B64Block(a).block
    b_poly = B64Block(b).block

    result = xex_gfmul(a_poly, b_poly)

    b64_result = Block(result).b64_block

    assert b64_result == "hSQAAAAAAAAAAAAAAAAAAA=="


def test_sea128_encrypt():
    test_key = "istDASeincoolerKEYrofg=="
    test_plaintext = "yv66vvrO263eyviIiDNEVQ=="

    byte_test_key = B64Block(test_key).block
    byte_test_plaintext = B64Block(test_plaintext).block

    byte_result = sea_encrypt(byte_test_key, byte_test_plaintext)
    b64_result = Block(byte_result).b64_block

    assert b64_result == "D5FDo3iVBoBN9gVi9/MSKQ=="


def test_sea_128_decrypt():
    test_key = "istDASeincoolerKEYrofg=="
    test_ciphertext = "D5FDo3iVBoBN9gVi9/MSKQ=="

    byte_test_key = B64Block(test_key).block
    byte_test_ciphertext = B64Block(test_ciphertext).block

    byte_result = sea_decrypt(byte_test_key, byte_test_ciphertext)
    b64_result = Block(byte_result).b64_block

    assert b64_result == "yv66vvrO263eyviIiDNEVQ=="


def test_fde_encrypt():
    key = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
    tweak = "6VXORr+YYHrd2nVe0OlA+Q=="
    input = "/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW"

    byte_key = B64Block(key).block
    byte_tweak = B64Block(tweak).block
    byte_input = B64Block(input).block

    solution = encrypt_xex(byte_key, byte_tweak, byte_input)
    b64_solution = Block(solution).b64_block

    assert b64_solution == "mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO"


def test_fde_decrypt():
    key = "B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0="
    tweak = "6VXORr+YYHrd2nVe0OlA+Q=="
    input = "lr/ItaYGFXCtHhdPndE65yg7u/GIdM9wscABiiFOUH2Sbyc2UFMlIRSMnZrYCW1a"

    byte_key = B64Block(key).block
    byte_tweak = B64Block(tweak).block
    byte_input = B64Block(input).block

    solution = decrypt_xex(byte_key, byte_tweak, byte_input)
    b64_solution = Block(solution).b64_block

    assert b64_solution == "SGV5IHdpZSBrcmFzcyBkYXMgZnVua3Rpb25pZXJ0IGphIG9mZmVuYmFyIGVjaHQu"


def test_gcm_xex_semantic():
    coefficients = [12, 127, 9, 0]

    coeff_xex = XEX_Coefficients(coefficients)

    gcm_coefficients = coeff_xex.gcm_coefficients
    coeff_gcm = GCM_Coefficients(gcm_coefficients)

    assert coeff_xex.block == coeff_gcm.block
    assert coeff_xex.b64_block == coeff_gcm.b64_block
    assert coeff_gcm.xex_coefficients == coeff_xex.xex_coefficients
    assert coeff_gcm.gcm_coefficients == coeff_gcm.gcm_coefficients

    poly = 1 << 127 | 1 << 12 | 1 << 9 | 1

    poly_xex = XEX_Poly(poly)

    gcm_poly = poly_xex.gcm_poly
    poly_gcm = GCM_Poly(gcm_poly)

    assert poly_gcm.block == poly_xex.block
    assert poly_gcm.b64_block == poly_xex.b64_block
    assert poly_gcm.xex_coefficients == poly_xex.xex_coefficients
    assert poly_gcm.gcm_coefficients == poly_xex.gcm_coefficients


def test_gcm_encrypt():
    key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
    nonce = "4gF+BtR3ku/PUQci"
    plaintext = "RGFzIGlzdCBlaW4gVGVzdA=="
    ad = "QUQtRGF0ZW4="

    byte_key = B64Block(key).block
    byte_nonce = B64Block(nonce).block
    byte_plaintext = B64Block(plaintext).block
    byte_ad = B64Block(ad).block

    ciphertext, tag, L, H = gcm_encrypt(
        byte_nonce,
        byte_key,
        byte_plaintext,
        byte_ad,
        aes_encrypt
    )

    assert Block(ciphertext).b64_block == "ET3RmvH/Hbuxba63EuPRrw=="
    assert Block(tag).b64_block == "Mp0APJb/ZIURRwQlMgNN/w=="
    assert Block(L).b64_block == "AAAAAAAAAEAAAAAAAAAAgA=="
    assert Block(H).b64_block == "Bu6ywbsUKlpmZXMQyuGAng=="

    ciphertext, tag, L, H = gcm_encrypt(
        byte_nonce,
        byte_key,
        byte_plaintext,
        byte_ad,
        sea_encrypt
    )

    assert Block(ciphertext).b64_block == "0cI/Wg4R3URfrVFZ0hw/vg=="
    assert Block(tag).b64_block == "ysDdzOSnqLH0MQ+Mkb23gw=="
    assert Block(L).b64_block == "AAAAAAAAAEAAAAAAAAAAgA=="
    assert Block(H).b64_block == "xhFcAUT66qWIpYz+Ch5ujw=="""


def test_gcm_decrypt():
    key = "Xjq/GkpTSWoe3ZH0F+tjrQ=="
    nonce = "4gF+BtR3ku/PUQci"
    ciphertext = "0cI/Wg4R3URfrVFZ0hw/vg=="
    ad = "QUQtRGF0ZW4="
    tag = "ysDdzOSnqLH0MQ+Mkb23gw=="

    byte_key = B64Block(key).block
    byte_nonce = B64Block(nonce).block
    byte_ciphertext = B64Block(ciphertext).block
    byte_ad = B64Block(ad).block
    byte_tag = B64Block(tag).block

    plaintext, authentic = gcm_decrypt(
        byte_nonce,
        byte_key,
        byte_ciphertext,
        byte_ad,
        byte_tag,
        aes_encrypt
    )

    print(B64Block("RGFzIGlzdCBlaW4gVGVzdA==").block)

    assert Block(plaintext).b64_block == "RGFzIGlzdCBlaW4gVGVzdA=="
    assert authentic is True

    key = "ByMrTiLP7isfBDL7vsKkOQ=="
    nonce = "VOkKCCnH4EYE1z4L"
    ciphertext = "UdpDzPAafM+y"
    ad = "UknNF3AKBaF/8GUnFUw="
    tag = "sN0+1fG+WSOHMswF7IBnZA=="

    byte_key = B64Block(key).block
    byte_nonce = B64Block(nonce).block
    byte_ciphertext = B64Block(ciphertext).block
    byte_ad = B64Block(ad).block
    byte_tag = B64Block(tag).block

    plaintext, authentic = gcm_decrypt(
        byte_nonce,
        byte_key,
        byte_ciphertext,
        byte_ad,
        byte_tag,
        sea_encrypt
    )

    assert Block(plaintext).b64_block == "AxSiKm93Gr2+"
    assert authentic is False

