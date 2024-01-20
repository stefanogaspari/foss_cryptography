# foss_cryptography

`foss_cryptography` is a Python free open source library for Elliptic Curves Cryptography under the MIT license.

The library provides:
1. the basic operations for the generic elliptic curve points: addition, doubling and scalar multiplication
2. the parameters of the secp256k1 elliptic curve
3. the ECDSA (Elliptic Curve Digital Signature Algorithm) for message signing and verification

The main functions of this library are self-contained, and the library doesn't require any external dependencies to perform its core operations.


## Features

- **Elliptic Curve Operations**: The library includes a module `ellipticCurves.py` that provides essential operations on elliptic curves, such as point doubling, point addition, and scalar multiplication.

- **ECDSA Implementation**: The `ecdsa.py` module implements the ECDSA algorithm, allowing users to sign and verify messages using the secp256k1 elliptic curve.


## Installation

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
from cyptography.secp256k1 import mod, a, b

# Initialize an elliptic curve
curve = EllipticCurve(mod, a, b)

# Point initialization
P = [x1, y1] # x1 and y1: type int
Q = [x2, y2] # x2 and y2: type int

# Point doubling
R = curve.double(P)

# Point addition
R = curve.add(P, Q)

# Scalar multiplication
result = curve.scalar_multiply(n, P)
```


### ECDSA

```python
from cryptography.ecdsa import ECDSA
from cyptography.secp256k1 import mod, a, b, origin_G, n


# Initialize ECDSA instance
ecdsa = ECDSA(m, a, b, origin_G, n)

# Sign a message
signature = ecdsa.sign(k, message, private_key)

# Verify a message
is_verified = ecdsa.verify(signature, message, public_key)
```


### License
This project is under the [MIT License](LICENSE).