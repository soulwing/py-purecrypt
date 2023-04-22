
from purecrypt.crypt import Crypt, Method
from purecrypt.crypt_md5 import CryptMD5
from purecrypt.crypt_sha2 import CryptSHA2
from purecrypt.crypt_sha256 import CryptSHA256
from purecrypt.crypt_sha512 import CryptSHA512


PASSWORD = "Hello world!"
SALT_STRING = "saltstring"


def test_encrypt_md5():
    ciphertext = Crypt.encrypt(PASSWORD, f"$1${SALT_STRING}")
    expected = "$1$saltstri$YMyguxXMBpd2TEZ.vS/3q1"
    assert ciphertext == expected
    assert Crypt.is_valid(PASSWORD, ciphertext)


def test_encrypt_sha256():
    ciphertext = Crypt.encrypt(PASSWORD, f"$5${SALT_STRING}")
    expected = "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"
    assert ciphertext == expected
    assert Crypt.is_valid(PASSWORD, ciphertext)


def test_encrypt_sha512():
    ciphertext = Crypt.encrypt(PASSWORD, f"$6${SALT_STRING}")
    expected = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"
    assert ciphertext == expected
    assert Crypt.is_valid(PASSWORD, ciphertext)


def test_generate_salt_md5():
    salt = Crypt.generate_salt(Method.MD5)
    assert salt.startswith(CryptMD5.SALT_PREFIX)
    assert len(salt) == len(CryptMD5.SALT_PREFIX) + CryptMD5.MAX_SALT_LENGTH


def test_generate_salt_sha256():
    salt = Crypt.generate_salt(Method.SHA256)
    assert salt.startswith(CryptSHA256.SALT_PREFIX)
    assert len(salt) == len(CryptSHA256.SALT_PREFIX) + CryptSHA2.MAX_SALT_LENGTH


def test_generate_salt_sha512():
    salt = Crypt.generate_salt(Method.SHA512)
    assert salt.startswith(CryptSHA512.SALT_PREFIX)
    assert len(salt) == len(CryptSHA512.SALT_PREFIX) + CryptSHA2.MAX_SALT_LENGTH
