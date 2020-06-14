def xtime(a):
    """ Multiplication of a(x) (binary polynomial) by x modulo m(x) = x**8 + x**4 + x**3 + x + 1

    (a & 0x80)  returns 0x0 if a > 0x80 (0b10000000), else returns 0x80
    (a & 0xff)  cuts to the last 8 bits of a number
    """
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)


class GF8:
    """
     Class representing a finite field GF(2 ** 8)
    """
    def __init__(self, val: int):
        self.value = val & 0xff      # elements in field should be in range(0, 256)

    def __add__(self, other):
        """ Addition in GF(2 ** 8)

        :param other: element to be added
        :return: self + other
        """
        if isinstance(other, int):
            other = GF8(other)
        return GF8(self.value ^ other.value)

    def __mul__(self, other):
        """ Multiplication in GF(2 ** 8)

        :param other: element to be multiplied by
        :return: self * other
        """
        if isinstance(other, int):
            other = GF8(other)
        res = 0
        for i in range(8):
            if 1 << i & other.value:
                buf = self.value
                for _ in range(i):
                    buf = xtime(buf)
                res ^= buf
        return GF8(res)

    def inv(self):
        """ Finds inverse of the element in GF(2 ** 8)

        Based on the Euler's theorem
        Since the nonzero elements of GF(p**n) form a finite group with respect to multiplication,
        a ** (p ** n − 1) = 1 (for a ≠ 0), thus the inverse of a is a ** (p ** n − 2)

        :return: self ** (-1)
        """
        if self.value == 0:
            return self
        res = GF8(1)
        power = self
        for i in range(8):
            if 1 << i & 254:
                res *= power
            power *= power
        return res

    def __repr__(self):
        return hex(self.value)

    def __str__(self):
        return hex(self.value)
