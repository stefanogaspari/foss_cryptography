# foss_cryptography

`foss_cryptography` is a Python free open source library for Elliptic Curves Cryptography under the [MIT License](LICENSE).

The library provides:
1. the basic operations for the generic elliptic curve points: addition, doubling and scalar multiplication
2. the ECDSA (Elliptic Curve Digital Signature Algorithm) for non-deterministic and deterministic message signing and signature verification
3. a library of parameters of some standard elliptic curves (NIST, etc.)

The main functions of this library are self-contained, and the library doesn't require any external dependencies to perform its core operations.


## Features

- **Elliptic Curve Operations**: The library includes a module `ellipticCurves.py` that provides essential operations on elliptic curves, such as point doubling, point addition, and scalar multiplication.

- **ECDSA Implementation**: The `ecdsa.py` module implements the ECDSA algorithm with non-deterministic and deterministic generation of k (RFC6979), allowing users to sign and verify messages using a provided library of standard elliptic curves.


## Installation

### From PyPI:

Install the library

```bash
pip install foss-cryptography
```

### From GitHub:

Clone the library from GitHub

```bash
git clone https://github.com/stefanogaspari/foss_cryptography.git
```

Install the library dependencies

```bash
pip install -r requirements.txt
```

Build the library

```bash
python setup.py bdist_wheel
```

Install the library
```bash
pip install /path/to/wheelfile.whl
```


## Usage

### Elliptic Curves

```python
from cryptography.ellipticCurves import EllipticCurve
from cyptography.secp256k1 import p, a, b

# Initialize an elliptic curve
curve = EllipticCurve(p, a, b)

# Point initialization
P = [x1, y1] # x1 and y1: type int
Q = [x2, y2] # x2 and y2: type int

# Point doubling R = 2 * P
R = curve.double(P)

# Point addition, R = P + Q
R = curve.add(P, Q)

# Scalar multiplication, R = n * P
R = curve.scalar_multiply(n, P)
```


### non-deterministic ECDSA

```python
from cryptography.ecdsa import ECDSA
from cyptography.curves.secp256k1 import p, a, b, origin_G, n

# Define the hash function
hash_function = 'sha256'

# Initialize ECDSA secp256k1 instance
ecdsa = ECDSA(m, a, b, origin_G, n, hash_function)

# Sign a message with a secure random k
# k: int
# message: bytes
# private_key: bytes
# signature: bytes -> r || s
signature = ecdsa.non_deterministic_sign(k, message, private_key)

# Verify a message
# message: bytes
# public_key: bytes -> public_key_x || public_key_y
# is_verified: bool
is_verified = ecdsa.verify(signature, message, public_key)
```


### deterministic ECDSA

```python
from cryptography.ecdsa import ECDSA
from cyptography.curves.secp256k1 import p, a, b, origin_G, n

# Define the hash function
hash_function = 'sha256'

# Initialize ECDSA secp256k1 instance
ecdsa = ECDSA(m, a, b, origin_G, n)

# Sign a message with a deterministic k (as per RFC6979)
# message: bytes
# private_key: bytes
# signature: bytes -> r || s
signature = ecdsa.deterministic_sign(message, private_key)

# Verify a message
# message: bytes
# public_key: bytes -> public_key_x || public_key_y
# is_verified: bool
is_verified = ecdsa.verify(signature, message, public_key)
```


## License
This project is under the [MIT License](LICENSE).