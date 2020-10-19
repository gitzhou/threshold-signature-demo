from modular_inverse import modular_multiplicative_inverse
from ec_point_operation import curve, add, scalar_multiply
from polynomial import Polynomial
from sign_message import message_digest, verify_message
from meta import public_key_to_address
from sign import hash_to_int
import random
from base64 import b64encode


class ThresholdSignature:

    @staticmethod
    def shares_to_points(shares: list) -> list:
        """Returns [(participant_id, share), (participant_id, share), ...]"""
        return [(i + 1, shares[i]) for i in range(len(shares))]

    @staticmethod
    def inspect(items: list) -> str:
        return f'[{", ".join([str(item) for item in items])}]'

    def __init__(self, group_size: int, threshold: int) -> None:
        if group_size < 3:
            raise ValueError(f'Nakasendo group size should be 3 at least')
        self.group_size = group_size
        # t
        self.polynomial_order = threshold - 1
        # t + 1
        self.key_threshold = self.polynomial_order + 1
        # 2t + 1
        self.signature_threshold = 2 * self.polynomial_order + 1
        # Validate t >= 1 and t + 1 <= n and 2t + 1 <= n
        if self.polynomial_order < 1 or self.key_threshold > group_size or self.signature_threshold > group_size:
            raise ValueError(f'Nakasendo threshold should be in interval [2, {(group_size - 1) // 2 + 1}] with {group_size} players')
        # Generate secret shares for each participants
        self.shares, self.public_key = self.jvrss()

    def jvrss(self, debug: bool = False) -> tuple:
        """Returns (shares_of_participants, group_shared_public_key)"""
        if debug:
            print('------------ jvrss ------------')
        # Random polynomials for each player
        polynomials = []
        for i in range(self.group_size):
            p = Polynomial.random(self.polynomial_order, debug)
            if debug:
                print(f'Player {i + 1} {p}')
            polynomials.append(p)
        # Calculate shares for each player
        shares = [0] * self.group_size
        for i in range(self.group_size):
            for j in range(self.group_size):
                fij = polynomials[i].evaluate(j + 1)
                shares[j] += fij
                if debug:
                    print(f'f{i + 1}({j + 1}) = {fij}', end='\t')
            if debug:
                print()
        for i in range(len(shares)):
            shares[i] %= curve.n
        # Calculate group shared public key
        public_key = None
        for i in range(self.group_size):
            public_key = add(public_key, scalar_multiply(polynomials[i].coefficients[0], curve.g))
        if debug:
            secret = sum([p.coefficients[0] for p in polynomials]) % curve.n
            mod_inv_secret = modular_multiplicative_inverse(secret, curve.n)
            print(f'secret = {secret}')
            print(f'mod_inv_secret = {mod_inv_secret}')
            print(f'public key = {public_key}')
            print(f'shares = {ThresholdSignature.inspect(shares)}')
            print('-------------------------------')
        return shares, public_key

    def addss(self, a_shares: list, b_shares: list, debug: bool = False) -> int:
        """Returns secret addition of a and b, with a shares and b shares, without knowing a and b"""
        assert len(a_shares) == self.group_size
        assert len(b_shares) == self.group_size
        if debug:
            print('------------ addss ------------')
            print(ThresholdSignature.inspect(a_shares))
            print(ThresholdSignature.inspect(b_shares))
        shares_addition = [(a_shares[i] + b_shares[i]) % curve.n for i in range(self.group_size)]
        # random pick (t + 1) points
        random_points = random.sample(ThresholdSignature.shares_to_points(shares_addition), self.polynomial_order + 1)
        secrets_addition = Polynomial.interpolate_evaluate(random_points, 0)
        if debug:
            print(f'shares addition = {ThresholdSignature.inspect(shares_addition)}')
            print(f'points picked = {ThresholdSignature.inspect(random_points)}')
            print(f'secrets addition = {secrets_addition}')
            print('-------------------------------')
        return secrets_addition

    def pross(self, a_shares: list, b_shares: list, debug: bool = False) -> int:
        """Returns secret product of a and b, with a shares and b shares, without knowing a and b"""
        assert len(a_shares) == self.group_size
        assert len(b_shares) == self.group_size
        if debug:
            print('------------ pross ------------')
            print(ThresholdSignature.inspect(a_shares))
            print(ThresholdSignature.inspect(b_shares))
        shares_product = [(a_shares[i] * b_shares[i]) % curve.n for i in range(self.group_size)]
        # random pick (2t + 1) points
        random_points = random.sample(ThresholdSignature.shares_to_points(shares_product), 2 * self.polynomial_order + 1)
        secrets_product = Polynomial.interpolate_evaluate(random_points, 0)
        if debug:
            print(f'shares product = {ThresholdSignature.inspect(shares_product)}')
            print(f'points picked = {ThresholdSignature.inspect(random_points)}')
            print(f'secrets product = {secrets_product}')
            print('-------------------------------')
        return secrets_product

    def invss(self, a_shares: list, debug: bool = False) -> list:
        """Returns shares of modular multiplicative inverse of a, with shares of a, without knowing a"""
        assert len(a_shares) == self.group_size
        if debug:
            print('------------ invss ------------')
            print(ThresholdSignature.inspect(a_shares))
        b, _ = self.jvrss(debug)
        u = self.pross(a_shares, b, debug)
        mod_inv_u = modular_multiplicative_inverse(u, curve.n)
        inverse_shares = [(mod_inv_u * bi) % curve.n for bi in b]
        if debug:
            print(f'u = {u}')
            print(f'mod_inv_u = {mod_inv_u}')
            print(f'inverse shares = {ThresholdSignature.inspect(inverse_shares)}')
            random_points = random.sample(ThresholdSignature.shares_to_points(inverse_shares), 2 * self.polynomial_order + 1)
            print(f'points picked = {ThresholdSignature.inspect(random_points)}')
            secret_inverse = Polynomial.interpolate_evaluate(random_points, 0)
            print(f'inverse secret = {secret_inverse}')
            print('-------------------------------')
        return inverse_shares

    def restore_key(self, points: list) -> int:
        """Restore key from given points [(participant_id, share), ...]"""
        if len(points) < self.key_threshold:
            raise ValueError(f'The number of points is less than the threshold')
        return Polynomial.interpolate_evaluate(points, 0)

    def sign_recoverable(self, message: bytes) -> tuple:
        """Create ECDSA compact signature (recovery_id, r, s) with private key shares"""
        e = hash_to_int(message)
        recovery_id, r, s = 0, 0, 0
        while not s:
            mod_inv_k_shares = []
            # Calculate final r
            while not r:
                k_shares, k_public_key = self.jvrss()
                k_x, k_y = k_public_key
                r = k_x % curve.n
                recovery_id = 0 | 2 if k_x > curve.n else 0 | k_y % 2
                mod_inv_k_shares = self.invss(k_shares)
            # Calculate shares of s for each participants
            s_shares = []
            for i in range(self.group_size):
                s_shares.append(((e + r * self.shares[i]) * mod_inv_k_shares[i]) % curve.n)
            # Interpolate shares of s to get final s
            s = Polynomial.interpolate_evaluate(random.sample(ThresholdSignature.shares_to_points(s_shares), self.signature_threshold), 0)
        return recovery_id, r, s

    def sign_message(self, plain_text: str) -> tuple:
        """Sign arbitrary message with private key shares, returns (p2pkh_address, serialized_compact_signature)"""
        d = message_digest(plain_text)
        # recovery signature
        recovery_id, r, s = self.sign_recoverable(d)
        # prefix = 27 + recovery_id + (4 if using compressed public key else 0)
        prefix = 27 + recovery_id + 4
        serialized_sig = prefix.to_bytes(1, byteorder='big') + r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        return public_key_to_address(self.public_key, compressed=True), b64encode(serialized_sig).decode('ascii')


if __name__ == '__main__':
    ts = ThresholdSignature(group_size=3, threshold=2)
    # Plain text to sign
    plain = 'Threshold Signature Scheme Sign Test\nPrivate key shares:\n' + ThresholdSignature.inspect(ts.shares)
    print(plain)
    print('------------------')
    # Sign message
    address, sig = ts.sign_message(plain)
    print(address, sig)
    print('------------------')
    # Verify signature
    print(verify_message(address, plain, sig))
