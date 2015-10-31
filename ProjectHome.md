**py-bcrypt-0.4 released 25-Aug-2013; including Python3 support, Windows compilation fixes and support for a KDF mode**

**If you are using a previous version, please upgrade to py-bcrypt-0.3 or later. It fixes a [security problem](https://code.google.com/p/py-bcrypt/source/detail?r=3bc365ff43736d26ff37e9f2a4084f37b381b569)**

py-bcrypt is a Python wrapper of OpenBSD's Blowfish password hashing code, as described in "A Future-Adaptable Password Scheme" by Niels Provos and David Mazières.

This system hashes passwords using a version of Bruce Schneier's Blowfish block cipher with modifications designed to raise the cost of off-line password cracking and frustrate fast hardware implementation. The computation cost of the algorithm is parametised, so it can be increased as computers get faster. The intent is to make a compromise of a password database less likely to result in an attacker gaining knowledge of the plaintext passwords (e.g. using John the Ripper).

As of py-bcrypt-0.4, this module can also be used as a Key Derivation Function (KDF) to turn a password and salt into a cryptographic key.

py-bcrypt requires Python 2.6 or later. Python3 is supported as of py-bcrypt 0.4.

py-bcrypt is licensed under a ISC/BSD licence. The underlying Blowfish and hashing code implementation is taken from OpenBSD's libc and is subject to a 4-term BSD license. See the LICENSE file for details.