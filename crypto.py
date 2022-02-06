import hashlib
from binascii import hexlify


def sha256(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def double_sha256(payload: bytes) -> bytes:
    return sha256(sha256(payload))


def double_sha256_checksum(payload: bytes) -> bytes:
    return double_sha256(payload)[:4]


def ripemd160_sha256(payload: bytes) -> bytes:
    return hashlib.new('ripemd160', sha256(payload)).digest()


BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def b58_encode(payload: bytes) -> str:
    pad = 0
    for byte in payload:
        if byte == 0:
            pad += 1
        else:
            break
    prefix = '1' * pad
    num = int.from_bytes(payload, 'big')
    result = ''
    while num > 0:
        num, remaining = divmod(num, 58)
        result = BASE58_ALPHABET[remaining] + result
    return prefix + result


def b58check_encode(payload: bytes) -> str:
    return b58_encode(payload + double_sha256_checksum(payload))


def b58_decode(encoded: str) -> bytes:
    pad = 0
    for char in encoded:
        if char == '1':
            pad += 1
        else:
            break
    prefix = b'\x00' * pad
    num = 0
    try:
        for char in encoded:
            num *= 58
            num += BASE58_ALPHABET.index(char)
    except KeyError:
        raise ValueError(f'Invalid base58 encoded "{encoded}"')
    # if num is 0 then (0).to_bytes will return b''
    return prefix + num.to_bytes((num.bit_length() + 7) // 8, 'big')


def b58check_decode(encoded: str) -> bytes:
    decoded = b58_decode(encoded)
    payload = decoded[:-4]
    decoded_checksum = decoded[-4:]
    hash_checksum = double_sha256_checksum(payload)
    if decoded_checksum != hash_checksum:
        raise ValueError(f'Decoded checksum {hexlify(decoded_checksum)} from "{hexlify(decoded)}" is not equal to hash checksum {hexlify(hash_checksum)}')
    return payload
