from ec_point_operation import curve
import random


class Polynomial:
    """
    Polynomial y = a0 * x^0 + a1 * x^1 + ... + at * x^t on finite field Secp256k1.n
    """

    @staticmethod
    def random(order: int, debug: bool = False) -> 'Polynomial':
        """Random a polynomial with the specific order"""
        if order < 1:
            raise ValueError(f'The polynomial order should be a positive integer.')
        range_stop = 10 if debug else curve.n
        coefficients = [random.randrange(1, range_stop)]
        for i in range(order):
            coefficients.append(random.randrange(1, range_stop))
        return Polynomial(coefficients)

    @staticmethod
    def interpolate_evaluate(points: list, x: int) -> int:
        """Lagrange interpolate with the giving points, then evaluate y at x"""
        if len(points) < 2:
            raise ValueError('Lagrange interpolation requires at least 2 points')
        # [(numerator, denominator) ...]
        lagrange = [(0, 0)] * len(points)
        # the product of all the denominator
        denominator_product = 1
        for i in range(len(points)):
            numerator, denominator = 1, 1
            for j in range(len(points)):
                if j != i:
                    numerator *= (x - points[j][0])
                    denominator *= (points[i][0] - points[j][0])
            lagrange[i] = (points[i][1] * numerator, denominator)
            denominator_product *= denominator
        numerator_sum = 0
        for (numerator, denominator) in lagrange:
            numerator_sum += numerator * denominator_product // denominator
        return (numerator_sum // denominator_product) % curve.n

    def __init__(self, coefficients: list) -> None:
        if len(coefficients) < 2:
            raise ValueError(f'The polynomial should have 2 coefficients at least.')
        self.order = len(coefficients) - 1
        self.coefficients = coefficients[:]

    def evaluate(self, x: int) -> int:
        """Calculate y for the specific x"""
        if x == 0:
            return self.coefficients[0]
        y, pow_x = 0, 1
        for i in range(len(self.coefficients)):
            y += self.coefficients[i] * pow_x
            pow_x *= x
        return y % curve.n

    def add(self, other: 'Polynomial') -> 'Polynomial':
        """Returns the polynomial = self + other"""
        coefficients = []
        i = 0
        while i < len(self.coefficients) and i < len(other.coefficients):
            coefficients.append(self.coefficients[i] + other.coefficients[i])
            i += 1
        while i < len(self.coefficients):
            coefficients.append(self.coefficients[i])
            i += 1
        while i < len(other.coefficients):
            coefficients.append(other.coefficients[i])
            i += 1
        for i in range(len(coefficients)):
            coefficients[i] %= curve.n
        return Polynomial(coefficients)

    def multiply(self, other: 'Polynomial') -> 'Polynomial':
        """Returns the polynomial = self * other"""
        coefficients = [0] * (self.order + other.order + 1)
        for i in range(len(self.coefficients)):
            for j in range(len(other.coefficients)):
                coefficients[i + j] += self.coefficients[i] * other.coefficients[j]
        for i in range(len(coefficients)):
            coefficients[i] %= curve.n
        return Polynomial(coefficients)

    def __str__(self) -> str:
        return f'<Polynomial order={self.order}, coefficients=[{", ".join(str(i) for i in self.coefficients)}]>'

    def __eq__(self, other: 'Polynomial') -> bool:
        return self.coefficients == other.coefficients


if __name__ == '__main__':
    a = 2

    f = Polynomial.random(order=3, debug=True)
    print(f'f = {f}')
    fa = f.evaluate(a)
    print(f'f({a}) = {fa}')

    g = Polynomial.random(order=4, debug=True)
    print(f'g = {g}')
    ga = g.evaluate(a)
    print(f'g({a}) = {ga}')

    v = f.add(g)
    assert v == g.add(f)
    print(f'v = f + g = {v}')
    va = v.evaluate(a)
    print(f'v({a}) = {va}')
    assert va == (fa + ga) % curve.n

    u = f.multiply(g)
    assert u == g.multiply(f)
    print(f'u = f * g = {u}')
    ua = u.evaluate(a)
    print(f'u({a}) = {ua}')
    assert ua == (fa * ga) % curve.n

    p = [(1, 350), (2, 770), (3, 1350)]
    assert Polynomial.interpolate_evaluate(p, 0) == 90
    assert Polynomial.interpolate_evaluate(p, 1) == 350
    assert Polynomial.interpolate_evaluate(p, 2) == 770
