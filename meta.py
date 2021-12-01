from ec_point_operation import curve
from crypto import ripemd160_sha256, b58check_encode, b58check_decode, sha256, b58_encode
from binascii import hexlify


def int_to_varint(value: int) -> bytes:
    if value <= 0xfc:
        return value.to_bytes(1, 'little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    else:
        return b'\xff' + value.to_bytes(8, 'little')


def serialize_public_key(public_key: tuple, compressed: bool = True) -> bytes:
    """Serialize public key point to compressed format (02 || x) or (03 || x), or uncompressed format (04 || x || y)"""
    x, y = public_key
    if compressed:
        return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(32, byteorder='big')
    return b'\x04' + x.to_bytes(32, byteorder='big') + y.to_bytes(32, byteorder='big')


def public_key_hash(public_key: tuple, compressed: bool = True) -> bytes:
    public_key_bytes = serialize_public_key(public_key, compressed)
    return ripemd160_sha256(public_key_bytes)


def public_key_to_address(public_key: tuple, compressed: bool = True) -> str:
    return b58check_encode(b'\x00' + public_key_hash(public_key, compressed))


def address_to_public_key_hash(address: str) -> bytes:
    """Decode p2pkh address to public key hash"""
    decoded = b58check_decode(address)
    assert decoded[:1] == b'\x00'
    return decoded[1:]


OP_DUP = b'\x76'
OP_HASH160 = b'\xa9'
OP_PUSH_20 = b'\x14'
OP_EQUALVERIFY = b'\x88'
OP_CHECKSIG = b'\xac'


def build_locking_script(pkh: bytes) -> bytes:
    """Build p2pkh locking script for the given public key hash"""
    script = OP_DUP + OP_HASH160 + OP_PUSH_20 + pkh + OP_EQUALVERIFY + OP_CHECKSIG
    return int_to_varint(len(script)) + script


def serialize_signature(signature: tuple) -> bytes:
    """Serialize ECDSA signature (r, s) to bitcoin strict DER format."""
    r, s = signature
    # BIP-62, BIP-66
    # Enforce low s value in signature
    # Using (curve.n - s) if s > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
    # https://en.bitcoin.it/wiki/Transaction_malleability
    if s > curve.n // 2:
        s = curve.n - s
    # r
    r_bytes = r.to_bytes(32, byteorder='big').lstrip(b'\x00')
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    serialized = bytes([2, len(r_bytes)]) + r_bytes
    # s
    s_bytes = s.to_bytes(32, byteorder='big').lstrip(b'\x00')
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    serialized += bytes([2, len(s_bytes)]) + s_bytes
    return bytes([0x30, len(serialized)]) + serialized


def deserialize_signature(serialized: bytes) -> tuple:
    """Deserialize ECDSA bitcoin DER formatted signature to (r, s)"""
    try:
        assert serialized[0] == 0x30
        assert int(serialized[1]) == len(serialized) - 2
        # r
        assert serialized[2] == 0x02
        r_len = int(serialized[3])
        r = int.from_bytes(serialized[4: 4 + r_len], byteorder='big')
        # s
        assert serialized[4 + r_len] == 0x02
        s_len = int(serialized[5 + r_len])
        s = int.from_bytes(serialized[-s_len:], byteorder='big')
        return r, s
    except Exception:
        raise ValueError(f'Invalid DER encoded {hexlify(serialized)}.')


def private_key_to_wif(private_key: int, compressed: bool = True) -> str:
    payload = b'\x80' + private_key.to_bytes(32, byteorder='big')
    if compressed:
        payload += b'\x01'
    checksum = sha256(sha256(payload))[0:4]
    return b58_encode(payload + checksum)


def wif_to_private_key(wif: str) -> int:
    if not wif.startswith('5') and not wif.startswith('K') and not wif.startswith('L'):
        raise ValueError(f'Invalid WIF {wif}')
    payload = b58check_decode(wif)
    if wif.startswith('K') or wif.startswith('L'):
        payload = payload[:-1]
    return int.from_bytes(payload[1:], byteorder='big')


if __name__ == '__main__':
    sig = (114587593887127314608220924841831336233967095853165151956820984900193959037698, 24000727837347392504013031837120627225728348681623127776947626422811445180558)
    serialized_sig = serialize_signature(sig)
    print(hexlify(serialized_sig))
    decoded_sig = deserialize_signature(serialized_sig)
    print(decoded_sig == sig)
