from ec_point_operation import curve, scalar_multiply
from meta import int_to_varint, address_to_public_key_hash, build_locking_script, deserialize_signature, serialize_signature, serialize_public_key
from crypto import double_sha256
from sign import verify_signature, sign
from collections import namedtuple
from binascii import unhexlify, hexlify

VERSION = 0x01.to_bytes(4, 'little')
SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
LOCK_TIME = 0x00.to_bytes(4, byteorder='little')

SH_ALL = 0x01
SH_FORKID = 0x40
SIGHASH_ALL = SH_ALL | SH_FORKID


class TxIn:
    def __init__(self, satoshi: int, txid: str, index: int, locking_script: str, sequence: bytes = SEQUENCE) -> None:
        self.satoshi = satoshi.to_bytes(8, byteorder='little')
        self.txid = unhexlify(txid)[::-1]
        self.index = index.to_bytes(4, byteorder='little')
        self.locking_script = unhexlify(locking_script)
        self.locking_script_len = int_to_varint(len(self.locking_script))
        self.unlocking_script = b''
        self.unlocking_script_len = b''
        self.sequence = sequence


TxOut = namedtuple('TxOut', 'address satoshi')


def serialize_outputs(outputs: list) -> bytes:
    """
    Serialize outputs [(address, satoshi), (address, satoshi), ...]
    to format (satoshi || LEN(locking_script) || locking_script) || (satoshi || LEN(locking_script) || locking_script) || ...)
    """
    output_bytes = b''
    for output in outputs:
        output_bytes += output.satoshi.to_bytes(8, byteorder='little') + build_locking_script(address_to_public_key_hash(output.address))
    return output_bytes


def transaction_digest(tx_ins: list, tx_outs: list, lock_time: bytes = LOCK_TIME, sighash: int = SIGHASH_ALL) -> list:
    """Returns the digest of unsigned transaction according to SIGHASH"""
    # BIP-143 https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    #  1. nVersion of the transaction (4-byte little endian)
    #  2. hashPrevouts (32-byte hash)
    #  3. hashSequence (32-byte hash)
    #  4. outpoint (32-byte hash + 4-byte little endian)
    #  5. scriptCode of the input (serialized as scripts inside CTxOuts)
    #  6. value of the output spent by this input (8-byte little endian)
    #  7. nSequence of the input (4-byte little endian)
    #  8. hashOutputs (32-byte hash)
    #  9. nLocktime of the transaction (4-byte little endian)
    # 10. sighash type of the signature (4-byte little endian)
    if sighash == SIGHASH_ALL:
        hash_prevouts = double_sha256(b''.join([tx_in.txid + tx_in.index for tx_in in tx_ins]))
        hash_sequence = double_sha256(b''.join([tx_in.sequence for tx_in in tx_ins]))
        hash_outputs = double_sha256(serialize_outputs(tx_outs))
        digests = []
        for tx_in in tx_ins:
            digests.append(
                VERSION +
                hash_prevouts + hash_sequence +
                tx_in.txid + tx_in.index + tx_in.locking_script_len + tx_in.locking_script + tx_in.satoshi + tx_in.sequence +
                hash_outputs +
                lock_time +
                sighash.to_bytes(4, byteorder='little')
            )
        return digests
    raise ValueError(f'Unsupported SIGHASH value {sighash}')


def serialize_transaction(tx_ins: list, tx_outs: list, lock_time: bytes = LOCK_TIME) -> bytes:
    """Serialize signed transaction"""
    # version
    raw_transaction = VERSION
    # inputs
    raw_transaction += int_to_varint(len(tx_ins))
    for tx_in in tx_ins:
        raw_transaction += tx_in.txid + tx_in.index + tx_in.unlocking_script_len + tx_in.unlocking_script + tx_in.sequence
    # outputs
    raw_transaction += int_to_varint(len(tx_outs)) + serialize_outputs(tx_outs)
    # lock_time
    raw_transaction += lock_time
    return raw_transaction


if __name__ == '__main__':
    priv_key = 0xf97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62
    pub_key = scalar_multiply(priv_key, curve.g)
    inputs = [
        TxIn(satoshi=1000, txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', index=1, locking_script='76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'),
        TxIn(satoshi=1000, txid='d2bc57099dd434a5adb51f7de38cc9b8565fb208090d9b5ea7a6b4778e1fdd48', index=2, locking_script='76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'),
        TxIn(satoshi=1000, txid='fcc1a53e8bb01dbc094e86cb86f195219022c26e0c03d6f18ea17c3a3ba3c1e4', index=0, locking_script='76a9146a176cd51593e00542b8e1958b7da2be97452d0588ac'),
    ]
    #
    # Verify the ECDSA signature of a signed transaction
    # 4674da699de44c9c5d182870207ba89e5ccf395e5101dab6b0900bbf2f3b16cb
    #
    tx_inputs = inputs[0:1]
    tx_outputs = [TxOut(address='1JDZRGf5fPjGTpqLNwjHFFZnagcZbwDsxw', satoshi=800)]
    tx_digest = transaction_digest(tx_inputs, tx_outputs)[0]
    serialized_sig = unhexlify('304402207e2c6eb8c4b20e251a71c580373a2836e209c50726e5f8b0f4f59f8af00eee1a022019ae1690e2eb4455add6ca5b86695d65d3261d914bc1d7abb40b188c7f46c9a5')
    sig = deserialize_signature(serialized_sig)
    print(verify_signature(pub_key, tx_digest, sig))
    #
    # Sign an unsigned transaction then broadcast
    # c04bbd007ad3987f9b2ea8534175b5e436e43d64471bf32139b5851adf9f477e
    #
    serialized_pub_key = serialize_public_key(pub_key)
    tx_inputs = inputs[1:]
    tx_outputs = [TxOut(address='18CgRLx9hFZqDZv75J5kED7ANnDriwvpi1', satoshi=1700)]
    tx_digests = transaction_digest(tx_inputs, tx_outputs)
    for i in range(len(tx_digests)):
        tx_digest = tx_digests[i]
        sig = sign(priv_key, tx_digest)
        serialized_sig = serialize_signature(sig)
        # unlocking_script = LEN + der + sighash + LEN + public_key
        tx_inputs[i].unlocking_script = bytes([len(serialized_sig) + 1]) + serialized_sig + bytes([SIGHASH_ALL, len(serialized_pub_key)]) + serialized_pub_key
        print(hexlify(tx_inputs[i].unlocking_script))
        tx_inputs[i].unlocking_script_len = int_to_varint(len(tx_inputs[i].unlocking_script))
        print(hexlify(tx_inputs[i].unlocking_script_len))
    raw = serialize_transaction(tx_inputs, tx_outputs)
    print(hexlify(raw))
    tx_id = double_sha256(raw)[::-1]
    print(hexlify(tx_id))
