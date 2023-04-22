from pytest import raises

from purecrypt.method import Method
from purecrypt.salt import Salt
from purecrypt.crypt_md5 import CryptMD5
from purecrypt.crypt_sha256 import CryptSHA256
from purecrypt.crypt_sha512 import CryptSHA512


def test_value_of():
    for method in Method:
        assert Method.value_of(method.name) is method

    with raises(ValueError):
        Method.value_of("UNKNOWN")


def test_for_salt():
    for method in Method:
        salt = Salt(f"${method.value}$salt$other")
        assert Method.for_salt(salt) is method

    with raises(ValueError):
        salt = Salt(f"$0$salt$other")
        Method.for_salt(salt)


def test_hash_provider():
    for method in Method:
        hash = method.hash_provider()
        assert hash.algorithm.name.upper() == method.name


def test_provider_class():
    assert Method.MD5.provider_class() is CryptMD5
    assert Method.SHA256.provider_class() is CryptSHA256
    assert Method.SHA512.provider_class() is CryptSHA512
