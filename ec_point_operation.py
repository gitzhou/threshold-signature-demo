import collections
from modular_inverse import modular_multiplicative_inverse

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    name='Secp256k1',
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    a=0,
    b=7,
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    h=1,
)


def on_curve(point: tuple) -> bool:
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True
    x, y = point
    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def negative(point: tuple) -> tuple or None:
    """Returns -point."""
    assert on_curve(point)
    if point is None:
        # -0 = 0
        return None
    x, y = point
    result = (x, -y % curve.p)
    assert on_curve(result)
    return result


def add(p: tuple, q: tuple) -> tuple or None:
    """Returns the result of p + q according to the group law."""
    assert on_curve(p)
    assert on_curve(q)
    if p is None:
        # 0 + q = q
        return q
    if q is None:
        # p + 0 = p
        return p
    #
    # p == -q
    #
    if p == negative(q):
        return None
    #
    # p != -q
    #
    x1, y1 = p
    x2, y2 = q
    if p == q:
        m = (3 * x1 * x1 + curve.a) * modular_multiplicative_inverse(2 * y1, curve.p)
    else:
        m = (y1 - y2) * modular_multiplicative_inverse(x1 - x2, curve.p)
    x = m * m - x1 - x2
    y = y1 + m * (x - x1)
    result = (x % curve.p, -y % curve.p)
    assert on_curve(result)
    return result


def scalar_multiply(k: int, point: tuple) -> tuple or None:
    """Returns k * point computed using the double and add algorithm."""
    assert on_curve(point)
    if k % curve.n == 0 or point is None:
        return None
    if k < 0:
        # k * point = -k * (-point)
        return scalar_multiply(-k, negative(point))
    # Double and add
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    assert on_curve(result)
    return result


if __name__ == '__main__':
    a = 0xf97c89aaacf0cd2e47ddbacc97dae1f88bec49106ac37716c451dcdd008a4b62
    print('a =', hex(a))
    ag = scalar_multiply(a, curve.g)
    print('x =', hex(ag[0]))
    print('y =', hex(ag[1]))

    from meta import public_key_to_address, private_key_to_wif

    print(private_key_to_wif(a))
    print(public_key_to_address(ag))
