from ec_point_operation import curve, add, scalar_multiply
from modular_inverse import modular_multiplicative_inverse
from crypto import double_sha256, sha256
import random


def hash_to_int(message: bytes) -> int:
    """Calculate the bitcoin double-sha256 hash of the message, return as an integer"""
    h = double_sha256(message)
    return int.from_bytes(h, byteorder='big')


def sign(private_key: int, message: bytes) -> tuple:
    """Create ECDSA signature (r, s)"""
    e = hash_to_int(message)
    r, s = 0, 0
    while not r or not s:
        k = random.randrange(1, curve.n)
        k_x, _ = scalar_multiply(k, curve.g)
        r = k_x % curve.n
        s = ((e + r * private_key) * modular_multiplicative_inverse(k, curve.n)) % curve.n
    return r, s


def sign_recoverable(private_key: int, message: bytes) -> tuple:
    """Create recoverable ECDSA signature, aka compact signature, (recovery_id, r, s)"""
    e = hash_to_int(message)
    recovery_id, r, s = 0, 0, 0
    while not r or not s:
        k = random.randrange(1, curve.n)
        k_x, k_y = scalar_multiply(k, curve.g)
        # r
        r = k_x % curve.n
        recovery_id = 0 | 2 if k_x > curve.n else 0 | k_y % 2
        # s
        s = ((e + r * private_key) * modular_multiplicative_inverse(k, curve.n)) % curve.n
    return recovery_id, r, s


def verify_signature(public_key: tuple, message: bytes, signature: tuple) -> bool:
    """Verify signature with public key and message"""
    e = hash_to_int(message)
    r, s = signature
    w = modular_multiplicative_inverse(s, curve.n)
    u1 = (w * e) % curve.n
    u2 = (w * r) % curve.n
    x, _ = add(scalar_multiply(u1, curve.g), scalar_multiply(u2, public_key))
    return r == (x % curve.n)


if __name__ == '__main__':
    priv_key = 0xf97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62
    pub_key = scalar_multiply(priv_key, curve.g)
    plain_text = '你好世界'
    digest = sha256(plain_text.encode('utf-8'))
    # Sign
    sig_r, sig_s = sign(priv_key, digest)
    print(' r =', sig_r)
    print(' s =', sig_s)
    # Verify (r, s)
    print(verify_signature(pub_key, digest, (sig_r, sig_s)))
    # Verify (r, -s)
    negative_s = -sig_s % curve.n
    print('-s =', negative_s)
    print(verify_signature(pub_key, digest, (sig_r, negative_s)))
