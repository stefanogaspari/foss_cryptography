import hashlib

def hash(msg: bytes, hash_function: str) -> bytes:
    hash = hashlib.new(hash_function)
    hash.update(msg)
    return hash.digest()

if __name__ == "__main__":
    print(hash(b'this is just a test', 'sha256'))