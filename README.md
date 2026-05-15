# python-slip10

A reference implementation of the [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) specification, which generalizes the [BIP-0032](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) derivation scheme for private and public key pairs in hierarchical deterministic wallets for the curves secp256k1, NIST P-256, ed25519 and curve25519.

## Usage

```python
>>> from slip10 import SLIP10, HARDENED_INDEX
>>> slip10 = SLIP10.from_seed(bytes.fromhex("01"))
# Specify the derivation path as a list ...
>>> slip10.get_xpriv_from_path([1, HARDENED_INDEX, 9998])
'xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts'
# ... Or in usual m/the/path/
>>> slip10.get_xpriv_from_path("m/1/0'/9998")
'xprv9y4sBgCuub5x2DtbdNBDDCZ3btybk8YZZaTvzV5rmYd3PbU63XLo2QEj6cUt4JAqpF8gJiRKFUW8Vm7thPkccW2DpUvBxASycypEHxmZzts'
>>> slip10.get_xpub_from_path([HARDENED_INDEX, 42])
'xpub69uEaVYoN1mZyMon8qwRP41YjYyevp3YxJ68ymBGV7qmXZ9rsbMy9kBZnLNPg3TLjKd2EnMw5BtUFQCGrTVDjQok859LowMV2SEooseLCt1'
# You can also use "h" or "H" to signal for hardened derivation
>>> slip10.get_xpub_from_path("m/0h/42")
'xpub69uEaVYoN1mZyMon8qwRP41YjYyevp3YxJ68ymBGV7qmXZ9rsbMy9kBZnLNPg3TLjKd2EnMw5BtUFQCGrTVDjQok859LowMV2SEooseLCt1'
# You can use pubkey-only derivation
>>> slip10 = SLIP10.from_xpub("xpub6AKC3u8URPxDojLnFtNdEPFkNsXxHfgRhySvVfEJy9SVvQAn14XQjAoFY48mpjgutJNfA54GbYYRpR26tFEJHTHhfiiZZ2wdBBzydVp12yU")
>>> slip10.get_xpub_from_path([42, 43])
'xpub6FL7T3s7GuVb4od1gvWuumhg47y6TZtf2DSr6ModQpX4UFGkQXw8oEVhJXcXJ4edmtAWCTrefD64B9RP4sYSkSumTW1wadTS3SYurBGYccT'
>>> slip10.get_xpub_from_path("m/42/43")
'xpub6FL7T3s7GuVb4od1gvWuumhg47y6TZtf2DSr6ModQpX4UFGkQXw8oEVhJXcXJ4edmtAWCTrefD64B9RP4sYSkSumTW1wadTS3SYurBGYccT'
>>> slip10.get_pubkey_from_path("m/1/1/1/1/1/1/1/1/1/1/1")
b'\x02\x0c\xac\n\xa8\x06\x96C\x8e\x9b\xcf\x83]\x0c\rCm\x06\x1c\xe9T\xealo\xa2\xdf\x195\xebZ\x9b\xb8\x9e'
```

## Installation

```
pip install slip10
```

### Dependencies

This package uses [`cryptography`](https://pypi.org/project/cryptography/) for Ed25519 and curve25519 operations.

### Running the test suite

#### Install uv, clone and enter python-slip10 repository

```
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/trezor/python-slip10
cd python-slip10
```

#### Run tests

```
make install
make test
```

## Interface

All public keys below are compressed.

All `path` below are a list of integers representing the index of the key at each depth.

`network` is "main" or "test".

`curve_name` is one of "secp256k1", "secp256r1", "ed25519" or "curve25519".

### SLIP10

#### from_seed(seed, network="main", curve_name="secp256k1")

__*classmethod*__

Instanciate from a raw seed (as `bytes`). See [SLIP-0010's master key
generation](https://github.com/satoshilabs/slips/blob/master/slip-0010.md#master-key-generation).

#### from_xpriv(xpriv)

__*classmethod*__

Instanciate with an encoded serialized extended private key (as `str`) as master.

#### from_xpub(xpub)

__*classmethod*__

Instanciate with an encoded serialized extended public key (as `str`) as master.

You'll only be able to derive unhardened public keys.

#### get_child_from_path(path)

Returns a SLIP10 instance of the child pointed by the path.

#### get_extended_privkey_from_path(path)

Returns `(chaincode (bytes), privkey (bytes))` of the private key pointed by the path.

#### get_privkey_from_path(path)

Returns `privkey (bytes)`, the private key pointed by the path.

#### get_extended_pubkey_from_path(path)

Returns `(chaincode (bytes), pubkey (bytes))` of the public key pointed by the path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

#### get_pubkey_from_path(path)

Returns `pubkey (bytes)`, the public key pointed by the path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

#### get_xpriv_from_path(path)

Returns `xpriv (str)` the serialized and encoded extended private key pointed by the given
path.

#### get_xpub_from_path(path)

Returns `xpub (str)` the serialized and encoded extended public key pointed by the given
path.

Note that you don't need to have provided the master private key if the path doesn't
include an index `>= HARDENED_INDEX`.

#### get_xpriv()

Equivalent to `get_xpriv_from_path([])`.

#### get_xpriv_bytes()

Equivalent to `get_xpriv([])`, but not serialized in base58.

#### get_xpub()

Equivalent to `get_xpub_from_path([])`.

#### get_xpub_bytes()

Equivalent to `get_xpub([])`, but not serialized in base58.

#### get_fingerprint()

Returns `fingerprint (bytes)`, equivalent to `utils._pubkey_to_fingerprint(self.pubkey)`.
