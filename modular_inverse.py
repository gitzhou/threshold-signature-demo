def extended_euclid_gcd(a: int, b: int) -> list:
    """
    Returns [gcd(a, b), x, y] where ax + by = gcd(a, b)
    """
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = b, a
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return [old_r, old_s, old_t]


def modular_multiplicative_inverse(a: int, n: int) -> int:
    """
    Assumes that a and n are co-prime, returns modular multiplicative inverse of a under n
    """
    # Find gcd using Extended Euclid's Algorithm
    gcd, x, y = extended_euclid_gcd(a, n)
    # In case x is negative, we handle it by adding extra n
    # Because we know that modular multiplicative inverse of a in range n lies in the range [0, n-1]
    if x < 0:
        x += n
    return x


if __name__ == '__main__':
    print(modular_multiplicative_inverse(3, 7))
