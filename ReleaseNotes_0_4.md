**the 0.4 release is not out yet, so these are just draft notes**

Changes in this release:

  * Added a bcrypt.checkpw() method to hash a password against a stored hash and verify that it matches.
  * Added a bcrypt.kdf() key derivation function method that is suitable for generating cryptographic key material.
  * Compilation fixes for Windows systems ([issue #1](https://code.google.com/p/py-bcrypt/issues/detail?id=#1), [issue #13](https://code.google.com/p/py-bcrypt/issues/detail?id=#13) and [issue #3](https://code.google.com/p/py-bcrypt/issues/detail?id=#3))
  * Python 3.x support ([issue #5](https://code.google.com/p/py-bcrypt/issues/detail?id=#5))