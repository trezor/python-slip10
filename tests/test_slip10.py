import os

import pytest

from slip10 import HARDENED_INDEX, SLIP10, InvalidInputError, PrivateDerivationError
from slip10.utils import SECP256K1

SEED_1 = "000102030405060708090a0b0c0d0e0f"
SEED_2 = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"


def test_bip32_vector_1():
    slip10 = SLIP10.from_seed(bytes.fromhex(SEED_1))
    # Chain m
    assert (
        slip10.get_xpub()
        == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    assert slip10.get_xpub_bytes() == bytes.fromhex(
        "0488b21e000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d5080339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
    )
    assert (
        slip10.get_xpriv()
        == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    assert slip10.get_xpriv_bytes() == bytes.fromhex(
        "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )
    # Chain m/0H
    assert (
        slip10.get_xpub_from_path([HARDENED_INDEX])
        == "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    )
    assert (
        slip10.get_xpriv_from_path([HARDENED_INDEX])
        == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    )
    assert slip10.get_xpub_from_path("m/0H") == slip10.get_xpub_from_path(
        [HARDENED_INDEX]
    )
    assert slip10.get_xpriv_from_path("m/0H") == slip10.get_xpriv_from_path(
        [HARDENED_INDEX]
    )
    # m/0H/1
    assert (
        slip10.get_xpub_from_path([HARDENED_INDEX, 1])
        == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    )
    assert (
        slip10.get_xpriv_from_path([HARDENED_INDEX, 1])
        == "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    )
    assert slip10.get_xpub_from_path("m/0'/1") == slip10.get_xpub_from_path(
        [HARDENED_INDEX, 1]
    )
    assert slip10.get_xpriv_from_path("m/0'/1") == slip10.get_xpriv_from_path(
        [HARDENED_INDEX, 1]
    )
    # m/0H/1/2H
    assert (
        slip10.get_xpub_from_path([HARDENED_INDEX, 1, HARDENED_INDEX + 2])
        == "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"
    )
    assert (
        slip10.get_xpriv_from_path([HARDENED_INDEX, 1, HARDENED_INDEX + 2])
        == "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    )
    assert slip10.get_xpub_from_path("m/0h/1/2h") == slip10.get_xpub_from_path(
        [HARDENED_INDEX, 1, HARDENED_INDEX + 2]
    )
    assert slip10.get_xpriv_from_path("m/0h/1/2h") == slip10.get_xpriv_from_path(
        [HARDENED_INDEX, 1, HARDENED_INDEX + 2]
    )
    # m/0H/1/2H/2
    assert (
        slip10.get_xpub_from_path([HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2])
        == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
    )
    assert (
        slip10.get_xpriv_from_path([HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2])
        == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    )
    assert (
        slip10.get_xpub_from_path("m/0'/1/2'/2")
        == "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"
    )
    assert (
        slip10.get_xpriv_from_path("m/0'/1/2'/2")
        == "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
    )
    # m/0H/1/2H/2/1000000000
    assert (
        slip10.get_xpub_from_path(
            [HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2, 1000000000]
        )
        == "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"
    )
    assert (
        slip10.get_xpriv_from_path(
            [HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2, 1000000000]
        )
        == "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"
    )
    assert slip10.get_xpub_from_path(
        "m/0H/1/2H/2/1000000000"
    ) == slip10.get_xpub_from_path(
        [HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2, 1000000000]
    )
    assert slip10.get_xpriv_from_path(
        "m/0H/1/2H/2/1000000000"
    ) == slip10.get_xpriv_from_path(
        [HARDENED_INDEX, 1, HARDENED_INDEX + 2, 2, 1000000000]
    )


def test_bip32_vector_2():
    slip10 = SLIP10.from_seed(bytes.fromhex(SEED_2))
    # Chain m
    assert (
        slip10.get_xpub()
        == "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
    )
    assert slip10.get_xpub_bytes() == bytes.fromhex(
        "0488b21e00000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd968903cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7"
    )
    assert (
        slip10.get_xpriv()
        == "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
    )
    assert slip10.get_xpriv_bytes() == bytes.fromhex(
        "0488ade400000000000000000060499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689004b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
    )
    # Chain m/0
    assert (
        slip10.get_xpub_from_path([0])
        == "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
    )
    assert (
        slip10.get_xpriv_from_path([0])
        == "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
    )
    assert slip10.get_xpriv_from_path("m/0") == slip10.get_xpriv_from_path([0])
    assert slip10.get_xpub_from_path("m/0") == slip10.get_xpub_from_path([0])
    # Chain m/0/2147483647H
    assert (
        slip10.get_xpub_from_path([0, HARDENED_INDEX + 2147483647])
        == "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"
    )
    assert (
        slip10.get_xpriv_from_path([0, HARDENED_INDEX + 2147483647])
        == "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9"
    )
    assert slip10.get_xpub_from_path("m/0/2147483647H") == slip10.get_xpub_from_path(
        [0, HARDENED_INDEX + 2147483647]
    )
    assert slip10.get_xpriv_from_path("m/0/2147483647H") == slip10.get_xpriv_from_path(
        [0, HARDENED_INDEX + 2147483647]
    )
    # Chain m/0/2147483647H/1
    assert (
        slip10.get_xpub_from_path([0, HARDENED_INDEX + 2147483647, 1])
        == "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
    )
    assert (
        slip10.get_xpriv_from_path([0, HARDENED_INDEX + 2147483647, 1])
        == "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
    )
    assert slip10.get_xpub_from_path("m/0/2147483647H/1") == slip10.get_xpub_from_path(
        [0, HARDENED_INDEX + 2147483647, 1]
    )
    assert slip10.get_xpriv_from_path(
        "m/0/2147483647H/1"
    ) == slip10.get_xpriv_from_path([0, HARDENED_INDEX + 2147483647, 1])
    # Chain m/0/2147483647H/1/2147483646H
    assert (
        slip10.get_xpub_from_path(
            [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646]
        )
        == "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
    )
    assert (
        slip10.get_xpriv_from_path(
            [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646]
        )
        == "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
    )
    assert slip10.get_xpub_from_path(
        "m/0/2147483647H/1/2147483646H"
    ) == slip10.get_xpub_from_path(
        [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646]
    )
    assert slip10.get_xpriv_from_path(
        "m/0/2147483647H/1/2147483646H"
    ) == slip10.get_xpriv_from_path(
        [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646]
    )
    # Chain m/0/2147483647H/1/2147483646H/2
    assert (
        slip10.get_xpub_from_path(
            [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646, 2]
        )
        == "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"
    )
    assert (
        slip10.get_xpriv_from_path(
            [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646, 2]
        )
        == "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j"
    )
    assert slip10.get_xpub_from_path(
        "m/0/2147483647H/1/2147483646H/2"
    ) == slip10.get_xpub_from_path(
        [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646, 2]
    )
    assert slip10.get_xpriv_from_path(
        "m/0/2147483647H/1/2147483646H/2"
    ) == slip10.get_xpriv_from_path(
        [0, HARDENED_INDEX + 2147483647, 1, HARDENED_INDEX + 2147483646, 2]
    )


def test_bip32_vector_3():
    seed = bytes.fromhex(
        "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
    )
    slip10 = SLIP10.from_seed(seed)
    # Chain m
    assert (
        slip10.get_xpub_from_path([])
        == "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"
    )
    assert (
        slip10.get_xpriv_from_path([])
        == "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
    )
    assert slip10.get_xpub_from_path("m") == slip10.get_xpub_from_path([])
    assert slip10.get_xpriv_from_path("m") == slip10.get_xpriv_from_path([])
    # Chain m/0H
    assert (
        slip10.get_xpub_from_path([HARDENED_INDEX])
        == "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
    )
    assert (
        slip10.get_xpriv_from_path([HARDENED_INDEX])
        == "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
    )
    assert slip10.get_xpub_from_path("m/0H") == slip10.get_xpub_from_path(
        [HARDENED_INDEX]
    )
    assert slip10.get_xpriv_from_path("m/0H") == slip10.get_xpriv_from_path(
        [HARDENED_INDEX]
    )


def test_bip32_vector_4():
    seed = bytes.fromhex(
        "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678"
    )
    slip10 = SLIP10.from_seed(seed)
    # Chain m
    assert (
        slip10.get_xpub_from_path("m")
        == "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"
    )
    assert (
        slip10.get_xpriv_from_path("m")
        == "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv"
    )
    # Chain m/0/H
    assert (
        slip10.get_xpub_from_path("m/0h")
        == "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"
    )
    assert (
        slip10.get_xpriv_from_path("m/0h")
        == "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G"
    )
    # Chain m/0H/1H
    assert (
        slip10.get_xpub_from_path("m/0h/1h")
        == "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"
    )
    assert (
        slip10.get_xpriv_from_path("m/0h/1h")
        == "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1"
    )


def test_bip32_vector_5():
    invalid_xpubs = [
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
    ]
    for xpub in invalid_xpubs:
        with pytest.raises(ValueError):
            SLIP10.from_xpub(xpub)

    invalid_xprivs = [
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
    ]
    for xpriv in invalid_xprivs:
        with pytest.raises(ValueError):
            SLIP10.from_xpriv(xpriv)


def test_sanity_checks():
    seed = bytes.fromhex(
        "1077a46dc8545d372f22d9e110ae6c5c2bf7620fe9c4c911f5404d112233e1aa270567dd3554092e051ba3ba86c303590b0309116ac89964ff284db2219d7511"
    )
    first_slip10 = SLIP10.from_seed(seed)
    sec_slip10 = SLIP10.from_xpriv(
        "xprv9s21ZrQH143K3o4KUs47P2x9afhH31ekMo2foNTYwrU9wwZ8g5EatR9bn6YmCacdvnHWMnPFUqieQrnunrzuF5UfgGbhbEW43zRnhpPDBUL"
    )
    assert first_slip10.get_xpriv() == sec_slip10.get_xpriv()
    assert first_slip10.get_xpub() == sec_slip10.get_xpub()
    # Fuzz it a bit
    for i in range(50):
        path = [int.from_bytes(os.urandom(3), "big") for _ in range(5)]
        h_path = [
            HARDENED_INDEX + int.from_bytes(os.urandom(3), "big") for _ in range(5)
        ]
        mixed_path = [int.from_bytes(os.urandom(3), "big") for _ in range(5)]
        for i in mixed_path:
            if int.from_bytes(os.urandom(32), "big") % 2:
                i += HARDENED_INDEX
        assert first_slip10.get_xpriv_from_path(path) == sec_slip10.get_xpriv_from_path(
            path
        )
        assert first_slip10.get_xpub_from_path(path) == sec_slip10.get_xpub_from_path(
            path
        )
        assert first_slip10.get_xpriv_from_path(
            h_path
        ) == sec_slip10.get_xpriv_from_path(h_path)
        assert first_slip10.get_xpub_from_path(h_path) == sec_slip10.get_xpub_from_path(
            h_path
        )
        assert first_slip10.get_xpriv_from_path(
            mixed_path
        ) == sec_slip10.get_xpriv_from_path(mixed_path)
        assert first_slip10.get_xpub_from_path(
            mixed_path
        ) == sec_slip10.get_xpub_from_path(mixed_path)

    # Taken from iancoleman's website
    slip10 = SLIP10.from_seed(
        bytes.fromhex(
            "ac8c2377e5cde867d7e420fbe04d8906309b70d51b8fe58d6844930621a9bc223929155dcfebb4da9d62c86ec0d15adf936a663f4f0cf39cbb0352e7dac073d6"
        )
    )
    assert (
        slip10.get_xpriv()
        == slip10.get_xpriv_from_path([])
        == "xprv9s21ZrQH143K2GzaKJsW7DQsxeDpY3zqgusaSx6owWGC19k4mhwnVAsm4qPsCw43NkY2h1BzVLyxWHt9NKF86QRyBj53vModdGcNxtpD6KX"
    )
    assert (
        slip10.get_xpub()
        == slip10.get_xpub_from_path([])
        == "xpub661MyMwAqRbcEm53RLQWUMMcWg4JwWih48oBFLWRVqoAsx5DKFG32yCEv8iH29TWpmo5KTcpsjXcea6Zx4Hc6PAbGnHjEDCf3yHbj7qdpnf"
    )
    # Sanity checks for m/0'/0'/14/0'/18
    path = [HARDENED_INDEX, HARDENED_INDEX, 14, HARDENED_INDEX, 18]
    xpriv = slip10.get_xpriv_from_path(path)
    xpub = slip10.get_xpub_from_path(path)
    assert xpriv == slip10.get_child_from_path(path).get_xpriv()
    assert xpub == slip10.get_child_from_path(path).get_xpub()
    assert (
        xpriv
        == "xprvA2YVbLvEeKaPedw7F6RLwG3RgYnTq1xGCyDNMgZNWdEQnSUBQmKEuLyA6TSPsggt5xvyJHLD9L25tNLpQiP4Q8ZkQNo8ueAgeYj5zYq8hSm"
    )
    assert (
        xpub
        == "xpub6FXqzrT8Uh8gs81aM7xMJPzAEacxEUg7aC8yA4xz4xmPfEoKxJdVT9Hdwm3LwVQrSos2rhGDt8aGGHvdLr5LLAjK8pXFkbSpzGoGTXjd4z9"
    )
    # Now if we our master is m/0'/0'/14, we should derive the same keys for
    # m/0'/18 !
    xpriv2 = slip10.get_xpriv_from_path(path[:3])
    assert (
        xpriv2
        == "xprv9yQJmvQMywM5i7UNuZ4RQ1A9rEMwAJCExPardkmBCB46S3vBqNEatSwLUrwLNLHBu1Kd9aGxGKDD5YAfs6hRzpYthciAHjtGadxgV2PeqY9"
    )
    slip10 = SLIP10.from_xpriv(xpriv2)
    assert slip10.get_xpriv() == xpriv2
    assert slip10.get_xpriv_from_path(path[3:]) == xpriv
    assert slip10.get_child_from_path(path[3:]).get_xpriv() == xpriv
    assert slip10.get_xpub_from_path(path[3:]) == xpub
    assert slip10.get_child_from_path(path[3:]).get_xpub() == xpub

    # We should recognize the networks..
    # .. for xprivs:
    slip10 = SLIP10.from_xpriv(
        "xprv9wHokC2KXdTSpEepFcu53hMDUHYfAtTaLEJEMyxBPAMf78hJg17WhL5FyeDUQH5KWmGjGgEb2j74gsZqgupWpPbZgP6uFmP8MYEy5BNbyET"
    )
    assert slip10.network == "main"
    slip10 = SLIP10.from_xpriv(
        "tprv8ZgxMBicQKsPeCBsMzQCCb5JcW4S49MVL3EwhdZMF1RF71rgisZU4ZRvrHX6PZQEiNUABDLvYqpx8Lsccq8aGGR59qHAoLoE3iXYuDa8JTP"
    )
    assert slip10.network == "test"
    # .. for xpubs:
    slip10 = SLIP10.from_xpub(
        "xpub6AHA9hZDN11k2ijHMeS5QqHx2KP9aMBRhTDqANMnwVtdyw2TDYRmF8PjpvwUFcL1Et8Hj59S3gTSMcUQ5gAqTz3Wd8EsMTmF3DChhqPQBnU"
    )
    assert slip10.network == "main"
    slip10 = SLIP10.from_xpub(
        "tpubD6NzVbkrYhZ4WN3WiKRjeo2eGyYNiKNg8vcQ1UjLNJJaDvoFhmR1XwJsbo5S4vicSPoWQBThR3Rt8grXtP47c1AnoiXMrEmFdRZupxJzH1j"
    )
    assert slip10.network == "test"

    # We should create valid network encoding..
    assert SLIP10.from_seed(os.urandom(32), "test").get_xpub().startswith("tpub")
    assert SLIP10.from_seed(os.urandom(32), "test").get_xpriv().startswith("tprv")
    assert SLIP10.from_seed(os.urandom(32), "main").get_xpub().startswith("xpub")
    assert SLIP10.from_seed(os.urandom(32), "main").get_xpriv().startswith("xprv")

    # We can get the keys from "m" or []
    slip10 = SLIP10.from_seed(os.urandom(32))
    assert (
        slip10.get_xpub()
        == slip10.get_xpub_from_path("m")
        == slip10.get_xpub_from_path([])
    )
    assert (
        slip10.get_xpriv()
        == slip10.get_xpriv_from_path("m")
        == slip10.get_xpriv_from_path([])
    )
    non_extended_pubkey = slip10.get_privkey_from_path("m")
    assert SECP256K1.privkey_to_pubkey(
        non_extended_pubkey
    ) == slip10.get_pubkey_from_path("m")
    # But getting from "m'" does not make sense
    with pytest.raises(ValueError, match="invalid format"):
        slip10.get_pubkey_from_path("m'")

    # We raise if we attempt to use a privkey without privkey access
    slip10 = SLIP10.from_xpub(
        "xpub6C6zm7YgrLrnd7gXkyYDjQihT6F2ei9EYbNuSiDAjok7Ht56D5zbnv8WDoAJGg1RzKzK4i9U2FUwXG7TFGETFc35vpQ4sZBuYKntKMLshiq"
    )
    slip10.get_xpub()
    slip10.get_pubkey_from_path("m/0/1")
    slip10.get_xpub_from_path("m/10000/18")
    with pytest.raises(PrivateDerivationError):
        slip10.get_xpriv()

    with pytest.raises(PrivateDerivationError):
        slip10.get_extended_privkey_from_path("m/0/1/2")

    with pytest.raises(PrivateDerivationError):
        slip10.get_privkey_from_path([9, 8])

    with pytest.raises(PrivateDerivationError):
        slip10.get_pubkey_from_path("m/0'/1")

    with pytest.raises(PrivateDerivationError):
        slip10.get_xpub_from_path("m/10000'/18")

    with pytest.raises(PrivateDerivationError):
        slip10.get_child_from_path("m/10000'/18")

    # Test get_child_from_path() public key derivation
    assert slip10.get_child_from_path(
        "m/10000/18"
    ).get_xpub() == slip10.get_xpub_from_path("m/10000/18")

    # We can't create a SLIP10 for an unknown network (to test InvalidInputError)
    with pytest.raises(InvalidInputError, match="'network' must be one of"):
        SLIP10.from_seed(os.urandom(32), network="invalid_net")


def test_slip10_vectors():
    vectors = [
        [
            # Test vector 1 for secp256k1
            [SEED_1, "secp256k1"],
            [
                "m",
                "00000000",
                "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
                "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
                "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
            ],
            [
                "m/0h",
                "3442193e",
                "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
                "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
                "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
            ],
            [
                "m/0h/1",
                "5c1bd648",
                "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
                "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
                "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
            ],
            [
                "m/0h/1/2h",
                "bef5a2f9",
                "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
                "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
                "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
            ],
            [
                "m/0h/1/2h/2",
                "ee7ab90c",
                "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
                "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
                "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
            ],
            [
                "m/0h/1/2h/2/1000000000",
                "d880d7d8",
                "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e",
                "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
                "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011",
            ],
        ],
        [
            # Test vector 1 for secp256r1
            [SEED_1, "secp256r1"],
            [
                "m",
                "00000000",
                "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
                "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
                "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
            ],
            [
                "m/0h",
                "be6105b5",
                "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11",
                "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c",
                "0384610f5ecffe8fda089363a41f56a5c7ffc1d81b59a612d0d649b2d22355590c",
            ],
            [
                "m/0h/1",
                "9b02312f",
                "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c",
                "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129",
                "03526c63f8d0b4bbbf9c80df553fe66742df4676b241dabefdef67733e070f6844",
            ],
            [
                "m/0h/1/2h",
                "b98005c1",
                "98c7514f562e64e74170cc3cf304ee1ce54d6b6da4f880f313e8204c2a185318",
                "694596e8a54f252c960eb771a3c41e7e32496d03b954aeb90f61635b8e092aa7",
                "0359cf160040778a4b14c5f4d7b76e327ccc8c4a6086dd9451b7482b5a4972dda0",
            ],
            [
                "m/0h/1/2h/2",
                "0e9f3274",
                "ba96f776a5c3907d7fd48bde5620ee374d4acfd540378476019eab70790c63a0",
                "5996c37fd3dd2679039b23ed6f70b506c6b56b3cb5e424681fb0fa64caf82aaa",
                "029f871f4cb9e1c97f9f4de9ccd0d4a2f2a171110c61178f84430062230833ff20",
            ],
            [
                "m/0h/1/2h/2/1000000000",
                "8b2b5c4b",
                "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059",
                "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119",
                "02216cd26d31147f72427a453c443ed2cde8a1e53c9cc44e5ddf739725413fe3f4",
            ],
        ],
        [
            # Test vector 1 for ed25519
            [SEED_1, "ed25519"],
            [
                "m",
                "00000000",
                "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
            ],
            [
                "m/0h",
                "ddebc675",
                "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            ],
            [
                "m/0h/1h",
                "13dab143",
                "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
            ],
            [
                "m/0h/1h/2h",
                "ebe4cb29",
                "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
            ],
            [
                "m/0h/1h/2h/2h",
                "316ec1c6",
                "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
            ],
            [
                "m/0h/1h/2h/2h/1000000000h",
                "d6322ccd",
                "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
            ],
        ],
        [
            # Test vector 1 for curve25519
            [SEED_1, "curve25519"],
            [
                "m",
                "00000000",
                "77997ca3588a1a34f3589279ea2962247abfe5277d52770a44c706378c710768",
                "d70a59c2e68b836cc4bbe8bcae425169b9e2384f3905091e3d60b890e90cd92c",
                "005c7289dc9f7f3ea1c8c2de7323b9fb0781f69c9ecd6de4f095ac89a02dc80577",
            ],
            [
                "m/0h",
                "6f5a9c0d",
                "349a3973aad771c628bf1f1b4d5e071f18eff2e492e4aa7972a7e43895d6597f",
                "cd7630d7513cbe80515f7317cdb9a47ad4a56b63c3f1dc29583ab8d4cc25a9b2",
                "00cb8be6b256ce509008b43ae0dccd69960ad4f7ff2e2868c1fbc9e19ec3ad544b",
            ],
            [
                "m/0h/1h",
                "fde474d7",
                "2ee5ba14faf2fe9d7ab532451c2be3a0a5375c5e8c44fb31d9ad7edc25cda000",
                "a95f97cfc1a61dd833b882c89d36a78a030ea6b2fbe3ae2a70e4f1fc9008d6b1",
                "00e9506455dce2526df42e5e4eb5585eaef712e5f9c6a28bf9fb175d96595ea872",
            ],
            [
                "m/0h/1h/2h",
                "6569dde7",
                "e1897d5a96459ce2a3d294cb2a6a59050ee61255818c50e03ac4263ef17af084",
                "3d6cce04a9175929da907a90b02176077b9ae050dcef9b959fed978bb2200cdc",
                "0018f008fcbc6d1cd8b4fe7a9eba00f6570a9da02a9b0005028cb2731b12ee4118",
            ],
            [
                "m/0h/1h/2h/2h",
                "1b7cce71",
                "1cccc84e2737cfe81b51fbe4c97bbdb000f6a76eddffb9ed03108fbff3ff7e4f",
                "7ae7437efe0a3018999e6f00d72e810ebc50578dbf6728bfa1c7fe73501081a7",
                "00512e288a8ef4d869620dc4b06bb06ad2524b350dee5a39fcfeb708dbac65c25c",
            ],
            [
                "m/0h/1h/2h/2h/1000000000h",
                "de5dcb65",
                "8ccf15d55b1dda246b0c1bf3e979a471a82524c1bd0c1eaecccf00dde72168bb",
                "7a59954d387abde3bc703f531f67d659ec2b8a12597ae82824547d7e27991e26",
                "00a077fcf5af53d210257d44a86eb2031233ac7237da220434ac01a0bebccc1919",
            ],
        ],
        [
            # Test vector 2 for secp256k1
            [
                SEED_2,
                "secp256k1",
            ],
            [
                "m",
                "00000000",
                "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
                "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
                "03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
            ],
            [
                "m/0",
                "bd16bee5",
                "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
                "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
                "02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
            ],
            [
                "m/0/2147483647h",
                "5a61ff8e",
                "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
                "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
                "03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
            ],
            [
                "m/0/2147483647h/1",
                "d8ab4937",
                "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
                "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
                "03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
            ],
            [
                "m/0/2147483647h/1/2147483646h",
                "78412e3a",
                "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
                "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
                "02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
            ],
            [
                "m/0/2147483647h/1/2147483646h/2",
                "31a507b8",
                "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271",
                "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
                "024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c",
            ],
        ],
        [
            # Test vector 2 for secp256r1
            [
                SEED_2,
                "secp256r1",
            ],
            [
                "m",
                "00000000",
                "96cd4465a9644e31528eda3592aa35eb39a9527769ce1855beafc1b81055e75d",
                "eaa31c2e46ca2962227cf21d73a7ef0ce8b31c756897521eb6c7b39796633357",
                "02c9e16154474b3ed5b38218bb0463e008f89ee03e62d22fdcc8014beab25b48fa",
            ],
            [
                "m/0",
                "607f628f",
                "84e9c258bb8557a40e0d041115b376dd55eda99c0042ce29e81ebe4efed9b86a",
                "d7d065f63a62624888500cdb4f88b6d59c2927fee9e6d0cdff9cad555884df6e",
                "039b6df4bece7b6c81e2adfeea4bcf5c8c8a6e40ea7ffa3cf6e8494c61a1fc82cc",
            ],
            [
                "m/0/2147483647h",
                "946d2a54",
                "f235b2bc5c04606ca9c30027a84f353acf4e4683edbd11f635d0dcc1cd106ea6",
                "96d2ec9316746a75e7793684ed01e3d51194d81a42a3276858a5b7376d4b94b9",
                "02f89c5deb1cae4fedc9905f98ae6cbf6cbab120d8cb85d5bd9a91a72f4c068c76",
            ],
            [
                "m/0/2147483647h/1",
                "218182d8",
                "7c0b833106235e452eba79d2bdd58d4086e663bc8cc55e9773d2b5eeda313f3b",
                "974f9096ea6873a915910e82b29d7c338542ccde39d2064d1cc228f371542bbc",
                "03abe0ad54c97c1d654c1852dfdc32d6d3e487e75fa16f0fd6304b9ceae4220c64",
            ],
            [
                "m/0/2147483647h/1/2147483646h",
                "931223e4",
                "5794e616eadaf33413aa309318a26ee0fd5163b70466de7a4512fd4b1a5c9e6a",
                "da29649bbfaff095cd43819eda9a7be74236539a29094cd8336b07ed8d4eff63",
                "03cb8cb067d248691808cd6b5a5a06b48e34ebac4d965cba33e6dc46fe13d9b933",
            ],
            [
                "m/0/2147483647h/1/2147483646h/2",
                "956c4629",
                "3bfb29ee8ac4484f09db09c2079b520ea5616df7820f071a20320366fbe226a7",
                "bb0a77ba01cc31d77205d51d08bd313b979a71ef4de9b062f8958297e746bd67",
                "020ee02e18967237cf62672983b253ee62fa4dd431f8243bfeccdf39dbe181387f",
            ],
        ],
        [
            # Test vector 2 for ed25519
            [
                SEED_2,
                "ed25519",
            ],
            [
                "m",
                "00000000",
                "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a",
            ],
            [
                "m/0h",
                "31981b50",
                "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
            ],
            [
                "m/0h/2147483647h",
                "1e9411b1",
                "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
            ],
            [
                "m/0h/2147483647h/1h",
                "fcadf38c",
                "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
            ],
            [
                "m/0h/2147483647h/1h/2147483646h",
                "aca70953",
                "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
            ],
            [
                "m/0h/2147483647h/1h/2147483646h/2h",
                "422c654b",
                "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4",
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                "0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
            ],
        ],
        [
            # Test vector 2 for curve25519
            [
                SEED_2,
                "curve25519",
            ],
            [
                "m",
                "00000000",
                "b62c0c81a80a0ee16b977abb3677eb47549d0eef090f7a6c2b2010e739875e34",
                "088491f5b4dfafbe956de471f3db10e02d784bc76050ee3b7c3f11b9706d3730",
                "0060cc3b40567729af08757e1efe62536dc864a57ec582f98b96f484201a260c7a",
            ],
            [
                "m/0h",
                "75edaf13",
                "341f386e571229e8adc52b82e824532817a31a35ba49ae334424e7228d020eed",
                "8e73218a1ba5c7b95e94b6e7cf7b37fb6240fb3b2ecd801402a4439da7067ee2",
                "007992b3f270ef15f266785fffb73246ad7f40d1fe8679b737fed0970d92cc5f39",
            ],
            [
                "m/0h/2147483647h",
                "5b26da66",
                "942cbec088b4ae92e8db9336025e9185fec0985a3da89d7a408bc2a4e18a8134",
                "29262b215c961bae20274588b33955c36f265c1f626df9feebb51034ce63c19d",
                "002372feac417c38b833e1aba75f2420278122d698605b995cafc2fed7bb453d41",
            ],
            [
                "m/0h/2147483647h/1h",
                "f701c832",
                "fe02397ae2ca71efe455f470fb23928baf026360a9e9090e21958f6fba9efc30",
                "a4d2474bd98c5e9ff416f536697b89949627d6d2c384b81a86d29f1136f4c2d1",
                "00eca4fd0458d3f729b6218eda871b350fa8870a744caf6d30cd84dad2b9dd9c2d",
            ],
            [
                "m/0h/2147483647h/1h/2147483646h",
                "6063347b",
                "b3b49d550e732ee629f4aeb4bf7213c3ae0f239fd10add513253cddbb8efb868",
                "d3500d9b30529c51d92497eded1d68d29f60c630c45c61a481c185e574c6e5cf",
                "00edaa3d381a2b02f40a80d69b2ce7ba7c3c4a9421744808857cd48c50d29b5868",
            ],
            [
                "m/0h/2147483647h/1h/2147483646h/2h",
                "86bf4fed",
                "f6ded904046e9758b9388dbf95ea5db837ab98b03b00e4db7009a8e3ac077685",
                "e20fecd59312b63b37eee27714465aae1caa1c87840abd0d685ea88b3d598fdf",
                "00aa705de68066e9534a238af35ea77c48016462a8aff358d22eaa6c7d5b034354",
            ],
        ],
        [
            # Test derivation retry for secp256r1
            [SEED_1, "secp256r1"],
            [
                "m",
                "00000000",
                "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea",
                "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2",
                "0266874dc6ade47b3ecd096745ca09bcd29638dd52c2c12117b11ed3e458cfa9e8",
            ],
            [
                "m/28578h",
                "be6105b5",
                "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2",
                "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669",
                "02519b5554a4872e8c9c1c847115363051ec43e93400e030ba3c36b52a3e70a5b7",
            ],
            [
                "m/28578h/33941",
                "3e2b7bc6",
                "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071",
                "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a",
                "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120",
            ],
        ],
        [
            # Test seed retry for secp256r1
            [
                "a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446",
                "secp256r1",
            ],
            [
                "m",
                "00000000",
                "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c",
                "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f",
                "0383619fadcde31063d8c5cb00dbfe1713f3e6fa169d8541a798752a1c1ca0cb20",
            ],
        ],
    ]

    for (seed, curve_name), *nodes in vectors:
        slip10 = SLIP10.from_seed(bytes.fromhex(seed), curve_name=curve_name)
        for path, parent_fingerprint, chaincode, privkey, pubkey in nodes:
            node = slip10.get_child_from_path(path)
            assert node.parent_fingerprint.hex() == parent_fingerprint
            assert node.chaincode.hex() == chaincode
            assert node.privkey.hex() == privkey
            assert node.pubkey.hex() == pubkey


def test_secp256r1_derivation_retry():
    # Test retry in public key to public key derivation
    # https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-derivation-retry-for-nist256p1
    chaincode, pubkey = SLIP10.from_seed(
        bytes.fromhex(SEED_1), curve_name="secp256r1"
    ).get_extended_pubkey_from_path("m/28578'")
    chaincode, pubkey = SLIP10(
        chaincode, pubkey=pubkey, curve_name="secp256r1"
    ).get_extended_pubkey_from_path("m/33941")
    assert (
        chaincode.hex()
        == "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071"
    )
    assert (
        pubkey.hex()
        == "0235bfee614c0d5b2cae260000bb1d0d84b270099ad790022c1ae0b2e782efe120"
    )
