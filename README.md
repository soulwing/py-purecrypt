py-purecrypt
============

A pure Python implementation of the crypt(3) function provided in the GNU C 
library (glibc). This implementation supports the MD5, SHA256, and SHA512 
variants.

This package provides a drop-in replacement for the deprecated (and soon to
be removed) `crypt` package provided in the Python standard library.

Because this is written in pure Python and depends only on the 
[cryptography](https://pypi.org/project/cryptography/) package, it should 
run on any platform supported by Python.

This implementation is not fast. If you're looking for speed, I suggest you
consider alternatives such as [bcrypt](https://pypi.org/project/bcrypt/).


Installation
------------

Install `py-purecrypt` from [PyPI](https://pypi.org/project/py-purecrypt)
using `pip` or your preferred Python package manager.


Usage
-----

This section shows basic usage examples.

### Using the Compatibility API

You can use this package as a drop-in replacement for the deprecated `crypt`
package that will soon be removed from the Python standard library. At present
this package supports only the MD5, SHA256, and SHA512 methods.

#### Example
```python
import purecrypt as crypt

plaintext_pw = "Hello world!"
salt = crypt.mksalt(crypt.METHOD_SHA256, rounds=10000)
hashed_pw = crypt.crypt(plaintext_pw, salt)
```

### Using the Native API

#### Encrypt a password

Choose a method and generate a salt, then encrypt.

```python
from purecrypt import Crypt, Method

plaintext_password = "super secret"
salt = Crypt.generate_salt(Method.SHA512)
ciphertext_password = Crypt.encrypt(plaintext_password, salt)
```

When generating a salt you can specify the number of rounds to perform
while encrypting.

```python
from purecrypt import Crypt, Method

plaintext_password = "super secret"
salt = Crypt.generate_salt(Method.SHA256, rounds=10000)
ciphertext_password = Crypt.encrypt(plaintext_password, salt)
```

#### Validate a password

To validate a given password, you just need the ciphertext that was produced
when the original password was encrypted.

```python
from purecrypt import Crypt

# as produced by the previous example
ciphertext_password = "$5$rounds=10000$vGuBkkhnTmd9BHeFpw4vxHNHJ1bxFRZX$2xiip3lO0cjGg3tZMdled9LpChHk1nmpF6hU6ZW05W1"

plaintext_password = "super secret"
assert Crypt.is_valid(plaintext_password, ciphertext_password)
```


