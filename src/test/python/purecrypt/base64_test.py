from purecrypt.b64 import encode


def test_encode():
    assert encode(0, 0, 0, 3) == "..."
    assert encode(0, 0, 0, 4) == "...."

    assert encode(255, 255, 255, 3) == "zzz"
    assert encode(255, 255, 255, 4) == "zzzz"

