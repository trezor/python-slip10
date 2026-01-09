import pytest

from slip10.utils import SECP256K1, SECP256R1


@pytest.mark.parametrize("curve", (SECP256K1, SECP256R1))
def test_curve_arithmetic(curve):
    generator = curve.multiply_generator(1)
    minus_generator = curve.multiply_generator(curve.order - 1)
    double_generator = curve.multiply_generator(2)
    triple_generator = curve.multiply_generator(3)

    assert curve.add_points(curve.point_at_infinity, generator) == generator
    assert curve.add_points(generator, curve.point_at_infinity) == generator
    assert curve.add_points(generator, minus_generator) == curve.point_at_infinity
    assert curve.add_points(generator, generator) == double_generator
    assert curve.add_points(generator, double_generator) == triple_generator

    assert curve.multiply_generator(0) == curve.point_at_infinity
    assert curve.multiply_generator(curve.order) == curve.point_at_infinity
    assert curve.multiply_generator(curve.order + 1) == generator
