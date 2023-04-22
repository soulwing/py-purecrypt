
from purecrypt.salt import Salt

from pytest import raises


def test_salt():

    with raises(ValueError):
        Salt("")

    with raises(ValueError):
        Salt("$")

    with raises(ValueError):
        Salt("$1")

    with raises(ValueError):
        Salt("$1$")

    salt = Salt("$1$s")
    assert salt.type == 1
    assert salt.text == "s"
    assert salt.params is None

    salt = Salt("$1$salt")
    assert salt.type == 1
    assert salt.text == "salt"
    assert salt.params is None

    salt = Salt("$1$salt$")
    assert salt.type == 1
    assert salt.text == "salt"
    assert salt.params is None

    salt = Salt("$1$salt$other")
    assert salt.type == 1
    assert salt.text == "salt"
    assert salt.params is None


def test_salt_with_params():
    salt = Salt("$1$=$salt")
    assert salt.type == 1
    assert salt.params == "="
    assert salt.text == "salt"

    salt = Salt("$1$=$salt$")
    assert salt.type == 1
    assert salt.params == "="
    assert salt.text == "salt"

    salt = Salt("$1$rounds=0$salt")
    assert salt.type == 1
    assert salt.params == "rounds=0"
    assert salt.text == "salt"

    salt = Salt("$1$rounds=0$salt$")
    assert salt.type == 1
    assert salt.params == "rounds=0"
    assert salt.text == "salt"

    salt = Salt("$1$rounds=0$salt$other")
    assert salt.type == 1
    assert salt.params == "rounds=0"
    assert salt.text == "salt"
