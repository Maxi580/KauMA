from typing import Dict, Any

from rsa_backdoor.glasskey import Glasskey
from rsa_backdoor.rsa import generate_rsa_key, rsa_key_to_bytes
from rsa_backdoor.glasskey_break import glasskey_break
from block_poly.b64 import B64
from block_poly.block import Block


def gcm_glasskey_prng_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    lengths = arguments["lengths"]

    gk = Glasskey(agency_key, seed)
    blocks = [gk.prng(length) for length in lengths]
    b64_blocks = [Block(block).b64 for block in blocks]

    return {"blocks": b64_blocks}


def gcm_prng_int_bits_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    bit_lengths = arguments["bit_lengths"]

    gk = Glasskey(agency_key, seed)
    ints = [gk.prng_int_bits(bit_length) for bit_length in bit_lengths]

    return {"ints": ints}


def glasskey_prng_int_min_max_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    specification = [(pair["min"], pair["max"]) for pair in arguments["specification"]]

    gk = Glasskey(agency_key, seed)
    ints = [gk.prng_int_min_max(m, M) for [m, M] in specification]

    return {"ints": ints}


def glasskey_genkey_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    agency_key = B64(arguments["agency_key"]).block
    seed = B64(arguments["seed"]).block
    bit_length = arguments["bit_length"]

    gk = Glasskey(agency_key, seed)
    p, q = gk.genkey(bit_length)
    der = generate_rsa_key(p, q)
    der_bytes = rsa_key_to_bytes(der)

    return {"der": Block(der_bytes).b64}


def glasskey_break_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    x509_crt = B64(arguments["x509_crt"]).block
    agency_key = B64(arguments["agency_key"]).block
    cms_msg = B64(arguments["cms_msg"]).block

    plaintext = glasskey_break(x509_crt, agency_key, cms_msg)

    return {"plaintext": Block(plaintext).b64}
