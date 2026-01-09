import hashlib
import hmac
import re

import ecdsa
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


class WeierstrassCurve:
    def __init__(self, name, modifier, curve):
        self.name = name
        self.modifier = modifier
        self.curve = curve

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
        # payload is the I from the SLIP. Index is 32 bits unsigned int, BE.
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
            child_private = (tweak + int.from_bytes(privkey, "big")) % self.curve.order
            if tweak < self.curve.order and child_private != 0:
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
        from ecdsa.ellipticcurve import INFINITY

        assert isinstance(pubkey, bytes) and isinstance(chaincode, bytes)
        if index & HARDENED_INDEX != 0:
            raise SLIP10DerivationError("Hardened derivation is not possible.")

        # payload is the I from the SLIP. Index is 32 bits unsigned int, BE.
        payload = hmac.new(
            chaincode, pubkey + index.to_bytes(4, "big"), hashlib.sha512
        ).digest()
        while True:
            tweak = int.from_bytes(payload[:32], "big")
            point = ecdsa.VerifyingKey.from_string(pubkey, self.curve).pubkey.point
            point += self.curve.generator * tweak
            if tweak < self.curve.order and point != INFINITY:
                break
            payload = hmac.new(
                chaincode,
                b"\x01" + payload[32:] + index.to_bytes(4, "big"),
                hashlib.sha512,
            ).digest()
        return point.to_bytes("compressed"), payload[32:]

    def privkey_is_valid(self, privkey):
        key = int.from_bytes(privkey, "big")
        return 0 < key < self.curve.order

    def pubkey_is_valid(self, pubkey):
        try:
            ecdsa.VerifyingKey.from_string(pubkey, self.curve)
            return True
        except ecdsa.errors.MalformedPointError:
            return False

    def privkey_to_pubkey(self, privkey):
        sk = ecdsa.SigningKey.from_string(privkey, self.curve)
        return sk.get_verifying_key().to_string("compressed")


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


SECP256K1 = WeierstrassCurve("secp256k1", b"Bitcoin seed", ecdsa.SECP256k1)
SECP256R1 = WeierstrassCurve("secp256r1", b"Nist256p1 seed", ecdsa.NIST256p)
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
