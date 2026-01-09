import pytest

from slip10.utils import SECP256K1, SECP256R1


def test_secp256k1():
    generator = SECP256K1.privkey_to_pubkey((1).to_bytes(32, "big"))
    minus_generator = SECP256K1.privkey_to_pubkey(
        (SECP256K1.curve.group_order - 1).to_bytes(32, "big")
    )
    double_generator = SECP256K1.privkey_to_pubkey((2).to_bytes(32, "big"))
    triple_generator = SECP256K1.privkey_to_pubkey((3).to_bytes(32, "big"))

    assert SECP256K1.add_points(generator, minus_generator) == bytes.fromhex("00")
    assert SECP256K1.add_points(generator, generator) == double_generator
    assert SECP256K1.add_points(generator, double_generator) == triple_generator


def test_secp256r1():
    generator = SECP256R1.privkey_to_pubkey((1).to_bytes(32, "big"))
    minus_generator = SECP256R1.privkey_to_pubkey(
        (SECP256R1.curve.group_order - 1).to_bytes(32, "big")
    )
    double_generator = SECP256R1.privkey_to_pubkey((2).to_bytes(32, "big"))
    triple_generator = SECP256R1.privkey_to_pubkey((3).to_bytes(32, "big"))

    assert SECP256R1.add_points(generator, minus_generator) == bytes.fromhex("00")
    assert SECP256R1.add_points(generator, generator) == double_generator
    assert SECP256R1.add_points(generator, double_generator) == triple_generator
