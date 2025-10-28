import hashlib
import hmac
import re
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

REGEX_DERIVATION_PATH = re.compile("^m(/[0-9]+['hH]?)*$")
HARDENED_INDEX = 0x80000000
ENCODING_PREFIX = {
    "main": {
        "private": 0x0488ADE4,
        "public": 0x0488B21E,
    },
    "test": {
        "private": 0x04358394,
        "public": 0x043587CF,
    },
}


class SLIP10DerivationError(Exception):
    pass


Point = Optional[Tuple[int, int]]


class WeierstrassCurve:
    def __init__(
        self,
        name: str,
        modifier: bytes,
        *,
        p: int,
        a: int,
        b: int,
        generator: Tuple[int, int],
        order: int,
    ):
        self.name = name
        self.modifier = modifier
        self.p = p
        self.a = a
        self.b = b
        self.generator = generator
        self.order = order
        self.coordinate_size = (p.bit_length() + 7) // 8

    def generate_master(self, seed):
        """Master key generation in SLIP-0010

        :param seed: Seed byte sequence (BIP-0039 binary seed or SLIP-0039 master secret), as bytes

        :return: (master_privatekey, master_chaincode)
        """
        while True:
            payload = hmac.new(self.modifier, seed, hashlib.sha512).digest()
            if self.privkey_is_valid(payload[:32]):
                return payload[:32], payload[32:]
            seed = payload

    def derive_private_child(self, privkey, chaincode, index):
        """A.k.a CKDpriv, in SLIP-0010, but the hardened way

        :param privkey: The parent's private key, as bytes
        :param chaincode: The parent's chaincode, as bytes
        :param index: The index of the node to derive, as int

        :return: (child_privatekey, child_chaincode)
        """
        assert isinstance(privkey, bytes) and isinstance(chaincode, bytes)
        if index & HARDENED_INDEX != 0:
            payload = hmac.new(
                chaincode, b"\x00" + privkey + index.to_bytes(4, "big"), hashlib.sha512
            ).digest()
        else:
            pubkey = self.privkey_to_pubkey(privkey)
            payload = hmac.new(
                chaincode, pubkey + index.to_bytes(4, "big"), hashlib.sha512
            ).digest()

        while True:
            tweak = int.from_bytes(payload[:32], "big")
            child_private = (tweak + int.from_bytes(privkey, "big")) % self.order
            if tweak <= self.order and child_private != 0:
                break
            payload = hmac.new(
                chaincode,
                b"\x01" + payload[32:] + index.to_bytes(4, "big"),
                hashlib.sha512,
            ).digest()

        return child_private.to_bytes(len(privkey), "big"), payload[32:]

    def derive_public_child(self, pubkey, chaincode, index):
        """A.k.a CKDpub, in SLIP-0010.

        :param pubkey: The parent's (compressed) public key, as bytes
        :param chaincode: The parent's chaincode, as bytes
        :param index: The index of the node to derive, as int

        :return: (child_pubkey, child_chaincode)
        """
        assert isinstance(pubkey, bytes) and isinstance(chaincode, bytes)
        if index & HARDENED_INDEX != 0:
            raise SLIP10DerivationError("Hardened derivation is not possible.")

        payload = hmac.new(
            chaincode, pubkey + index.to_bytes(4, "big"), hashlib.sha512
        ).digest()
        base_point = self._bytes_to_point(pubkey)
        while True:
            tweak = int.from_bytes(payload[:32], "big")
            tweak_point = self._scalar_mult(tweak, self.generator)
            child_point = self._point_add(base_point, tweak_point)
            if tweak <= self.order and child_point is not None:
                break
            payload = hmac.new(
                chaincode,
                b"\x01" + payload[32:] + index.to_bytes(4, "big"),
                hashlib.sha512,
            ).digest()
        return self._point_to_bytes(child_point), payload[32:]

    def privkey_is_valid(self, privkey):
        key = int.from_bytes(privkey, "big")
        return 0 < key < self.order

    def pubkey_is_valid(self, pubkey):
        try:
            point = self._bytes_to_point(pubkey)
        except ValueError:
            return False
        return point is not None and self._is_on_curve(point)

    def privkey_to_pubkey(self, privkey):
        if not self.privkey_is_valid(privkey):
            raise ValueError("Invalid private key")
        scalar = int.from_bytes(privkey, "big")
        point = self._scalar_mult(scalar, self.generator)
        if point is None:
            raise ValueError("Point at infinity")
        return self._point_to_bytes(point)

    def _is_on_curve(self, point: Point) -> bool:
        if point is None:
            return True
        x, y = point
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def _point_add(self, p1: Point, p2: Point) -> Point:
        if p1 is None:
            return p2
        if p2 is None:
            return p1
        if p1 == p2:
            return self._point_double(p1)

        x1, y1 = p1
        x2, y2 = p2
        if x1 == x2:
            return None

        slope = ((y2 - y1) * self._inverse_mod((x2 - x1) % self.p)) % self.p
        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        return x3, y3

    def _point_double(self, point: Point) -> Point:
        if point is None:
            return None
        x, y = point
        if y == 0:
            return None

        slope = ((3 * x * x + self.a) * self._inverse_mod((2 * y) % self.p)) % self.p
        x3 = (slope * slope - 2 * x) % self.p
        y3 = (slope * (x - x3) - y) % self.p
        return x3, y3

    def _scalar_mult(self, scalar: int, point: Tuple[int, int]) -> Point:
        scalar %= self.order
        if scalar == 0 or point is None:
            return None

        result: Point = None
        addend: Point = point
        while scalar:
            if scalar & 1:
                result = self._point_add(result, addend)
            addend = self._point_double(addend)
            scalar >>= 1
        return result

    def _bytes_to_point(self, data: bytes) -> Point:
        if len(data) == self.coordinate_size * 2 + 1 and data[0] == 4:
            x = int.from_bytes(data[1 : 1 + self.coordinate_size], "big")
            y = int.from_bytes(data[1 + self.coordinate_size :], "big")
            point = (x, y)
            if not self._is_on_curve(point):
                raise ValueError("Point is not on curve")
            return point

        if len(data) != self.coordinate_size + 1 or data[0] not in (2, 3):
            raise ValueError("Invalid public key encoding")

        x = int.from_bytes(data[1:], "big")
        y = self._recover_y(x, data[0] == 3)
        point = (x, y)
        if not self._is_on_curve(point):
            raise ValueError("Point is not on curve")
        return point

    def _point_to_bytes(self, point: Tuple[int, int]) -> bytes:
        x, y = point
        prefix = 0x03 if y & 1 else 0x02
        return bytes([prefix]) + x.to_bytes(self.coordinate_size, "big")

    def _recover_y(self, x: int, is_odd: bool) -> int:
        if x >= self.p:
            raise ValueError("Invalid point")
        rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        y = pow(rhs, (self.p + 1) // 4, self.p)
        if (y * y) % self.p != rhs:
            raise ValueError("Invalid point")
        if bool(y & 1) != is_odd:
            y = (-y) % self.p
        if bool(y & 1) != is_odd:
            raise ValueError("Invalid point")
        return y

    def _inverse_mod(self, value: int) -> int:
        return pow(value % self.p, -1, self.p)


class EdwardsCurve:
    def __init__(self, name, modifier, private_key_class, public_key_class):
        self.name = name
        self.modifier = modifier
        self.private_key_class = private_key_class
        self.public_key_class = public_key_class

    def generate_master(self, seed):
        """Master key generation in SLIP-0010

        :param seed: Seed byte sequence (BIP-0039 binary seed or SLIP-0039 master secret), as bytes

        :return: (master_privatekey, master_chaincode)
        """
        secret = hmac.new(self.modifier, seed, hashlib.sha512).digest()
        return secret[:32], secret[32:]

    def derive_private_child(self, privkey, chaincode, index):
        """A.k.a CKDpriv, in SLIP-0010, but the hardened way

        :param privkey: The parent's private key, as bytes
        :param chaincode: The parent's chaincode, as bytes
        :param index: The index of the node to derive, as int

        :return: (child_privatekey, child_chaincode)
        """
        assert isinstance(privkey, bytes) and isinstance(chaincode, bytes)
        # payload is the I from the SLIP. Index is 32 bits unsigned int, BE.
        if index & HARDENED_INDEX == 0:
            raise SLIP10DerivationError("Normal derivation is not supported.")

        payload = hmac.new(
            chaincode, b"\x00" + privkey + index.to_bytes(4, "big"), hashlib.sha512
        ).digest()

        return payload[:32], payload[32:]

    def derive_public_child(self, pubkey, chaincode, index):
        raise SLIP10DerivationError("Normal derivation is not supported.")

    def privkey_is_valid(self, privkey):
        try:
            self.private_key_class.from_private_bytes(privkey)
        except ValueError:
            return False
        return True

    def pubkey_is_valid(self, pubkey):
        if pubkey[0] != 0:
            return False

        try:
            self.public_key_class.from_public_bytes(pubkey[1:])
        except ValueError:
            return False
        return True

    def privkey_to_pubkey(self, privkey):
        from cryptography.hazmat.primitives import serialization

        sk = self.private_key_class.from_private_bytes(privkey)
        key_encoding = serialization.Encoding.Raw
        key_format = serialization.PublicFormat.Raw
        return b"\x00" + sk.public_key().public_bytes(key_encoding, key_format)


SECP256K1 = WeierstrassCurve(
    "secp256k1",
    b"Bitcoin seed",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0,
    b=7,
    generator=(
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    ),
    order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)
SECP256R1 = WeierstrassCurve(
    "secp256r1",
    b"Nist256p1 seed",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    generator=(
        0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    ),
    order=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
ED25519 = EdwardsCurve("ed25519", b"ed25519 seed", Ed25519PrivateKey, Ed25519PublicKey)
X25519 = EdwardsCurve(
    "curve25519", b"curve25519 seed", X25519PrivateKey, X25519PublicKey
)
CURVES = (SECP256K1, SECP256R1, ED25519, X25519)


def _get_curve_by_name(name):
    for curve in CURVES:
        if curve.name == name:
            return curve
    raise ValueError(
        "'curve' must be one of " + ", ".join(curve.name for curve in CURVES)
    )


def _ripemd160(data):
    try:
        rip = hashlib.new("ripemd160")
        rip.update(data)
        return rip.digest()
    except BaseException:
        # Implementations may ship hashlib without ripemd160.
        # In that case, fallback to custom pure Python implementation.
        # WARNING: the implementation in ripemd160.py is not constant-time.
        from . import ripemd160

        return ripemd160.ripemd160(data)


def _pubkey_to_fingerprint(pubkey):
    return _ripemd160(hashlib.sha256(pubkey).digest())[:4]


def _serialize_extended_key(key, depth, parent, index, chaincode, network="main"):
    """Serialize an extended private *OR* public key, as spec by SLIP-0010.

    :param key: The public or private key to serialize. Note that if this is
                a public key it MUST be compressed.
    :param depth: 0x00 for master nodes, 0x01 for level-1 derived keys, etc..
    :param parent: The parent pubkey used to derive the fingerprint, or the
                   fingerprint itself None if master.
    :param index: The index of the key being serialized. 0x00000000 if master.
    :param chaincode: The chain code (not the labs !!).

    :return: The serialized extended key.
    """
    for param in {key, chaincode}:
        assert isinstance(param, bytes)
    for param in {depth, index}:
        assert isinstance(param, int)
    if parent:
        assert isinstance(parent, bytes)
        if len(parent) == 33:
            fingerprint = _pubkey_to_fingerprint(parent)
        elif len(parent) == 4:
            fingerprint = parent
        else:
            raise ValueError("Bad parent, a fingerprint or a pubkey is" " required")
    else:
        fingerprint = bytes(4)  # master
    # A privkey or a compressed pubkey
    assert len(key) in {32, 33}
    if network not in {"main", "test"}:
        raise ValueError("Unsupported network")
    is_privkey = len(key) == 32
    prefix = ENCODING_PREFIX[network]["private" if is_privkey else "public"]
    extended = prefix.to_bytes(4, "big")
    extended += depth.to_bytes(1, "big")
    extended += fingerprint
    extended += index.to_bytes(4, "big")
    extended += chaincode
    if is_privkey:
        extended += b"\x00"
    extended += key
    return extended


def _unserialize_extended_key(extended_key):
    """Unserialize an extended private *OR* public key, as spec by SLIP-0010.

    :param extended_key: The extended key to unserialize __as bytes__

    :return: network (str), depth (int), fingerprint (bytes), index (int),
             chaincode (bytes), key (bytes)
    """
    assert isinstance(extended_key, bytes) and len(extended_key) == 78
    prefix = int.from_bytes(extended_key[:4], "big")
    network = None
    if prefix in list(ENCODING_PREFIX["main"].values()):
        network = "main"
    elif prefix in list(ENCODING_PREFIX["test"].values()):
        network = "test"
    depth = extended_key[4]
    fingerprint = extended_key[5:9]
    index = int.from_bytes(extended_key[9:13], "big")
    chaincode, key = extended_key[13:45], extended_key[45:]
    return network, depth, fingerprint, index, chaincode, key


def _hardened_index_in_path(path):
    return len([i for i in path if i & HARDENED_INDEX]) > 0


def _deriv_path_str_to_list(strpath):
    """Converts a derivation path as string to a list of integers
       (index of each depth)

    :param strpath: Derivation path as string with "m/x/x'/x" notation.
                    (e.g. m/0'/1/2'/2 or m/0H/1/2H/2 or m/0h/1/2h/2)

    :return: Derivation path as a list of integers (index of each depth)
    """
    if not REGEX_DERIVATION_PATH.match(strpath):
        raise ValueError("invalid format")
    indexes = strpath.split("/")[1:]
    list_path = []
    for i in indexes:
        # if HARDENED
        if i[-1:] in ["'", "h", "H"]:
            list_path.append(int(i[:-1]) + HARDENED_INDEX)
        else:
            list_path.append(int(i))
    return list_path
