import pytest

from slip10.utils import SECP256K1, SECP256R1


@pytest.mark.parametrize("curve", (SECP256K1, SECP256R1))
def test_curve_arithmetic(curve):
    generator = curve.privkey_to_pubkey((1).to_bytes(32, "big"))
    minus_generator = curve.privkey_to_pubkey(
        (curve.curve.group_order - 1).to_bytes(32, "big")
    )
    double_generator = curve.privkey_to_pubkey((2).to_bytes(32, "big"))
    triple_generator = curve.privkey_to_pubkey((3).to_bytes(32, "big"))

    assert curve.add_points(generator, minus_generator) == bytes.fromhex("00")
    assert curve.add_points(generator, generator) == double_generator
    assert curve.add_points(generator, double_generator) == triple_generator
