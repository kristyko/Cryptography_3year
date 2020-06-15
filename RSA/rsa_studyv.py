import os
import random


def euclidian_extended(a, b):
    """ Extended euclidian algorithm

    a * x + b * y = gcd(a, b)    (b > a)
    If gcd(a, b) = 1   then x - is a multiplicative inverse of a modulo b
                            y - is a multiplicative inverse of b modulo a

    :return:  x = gcd(a, b)
              s0 - multiplicative inverse of a (mod b) if a and b are coprime, None otherwise
    """
    s0, s1 = 0, 1
    x, y = b, a
    while y != 0:
        q = x // y
        x, y = y, x % y
        s0, s1 = s1, s0 - q * s1
    if x == 1:
        if s0 < 0:
            s0 += b
        return x, s0
    else:
        return x, None


def fast_exp(x, y, z):
    """  Fast modular exponentiation by squaring

    Example: 5 ** 117 (mod 19)
             117 = 0b1110101
             5 ** 117 (mod 19) = 5 ** (2**0 + 2**2 + 2**4 + 2**5 + 2**6) (mod 19) =
                               = 5**1 * 5**4 * 5**16 * 5**32 * 5**64 (mod 19)

             x ** 2i (mod y) = (x ** i (mod z)) * (x ** i (mod z)) (mod z)

    :return: x ** y (mod z)
    """
    i = 1
    power, res = x, 1
    for _ in range(y.bit_length()):
        if i & y:  # check if next bit of y equals 1
            res = res * power % z
        power = power * power % z
        i <<= 1
    return res


def miller_rabin_test(n):
    """ Miller-Rabin primality test

    Let n be prime. Then n - 1 = m * 2 ** s
    Then for any a from Z_n at least one is true:
      - a ** m = 1 (mod n)
      - a ** (m * 2 ** r) = -1 (mod n) for some r < s
    If for some a none of the above is true, then n isn't prime and a is called a witness of compositness of n

    :param n: integer to be tested for primality
    :return: True if n is prime, False - otherwise
    """
    s, m = 0, n - 1  # set s and m, according to n - 1 = m * 2**s
    while m % 2 == 0:
        m //= 2
        s += 1
    if s == 0:
        return False  # if n isn't odd then obviously it's not prime

    n_length = n.bit_length()
    if n_length >= 1024:
        K = 4
    elif n_length >= 512:
        K = 8
    elif n_length >= 256:
        K = 17
    else:
        K = 20
    for _ in range(K):
        a = random.randint(2, n - 2)
        b = fast_exp(a, m, n)  # b = a ** m (mod n)    (if n is prime then b could be 1 or -1)
        if b != 1 and b != n - 1:
            i = 1
            while i < s and b != n - 1:  # check if b = a ** (2 ** r) * d = -1 for any r < s
                b = (b * b) % n
                if b == 1: return False
                i += 1
            if b != n - 1: return False
    return True


def get_random_odd(size):
    """ Generates random odd integer of desired size

    :param size: bit length of a number to be generated
    :return:
    """
    s, r = size // 8, size % 8
    num = int.from_bytes(os.urandom(s), byteorder='big')
    if r > 0:
        tail = int.from_bytes(os.urandom(1), byteorder='big') >> (8 - r)
        num = (num << r) ^ tail
    num |= 1 << (size - 1) | 1      # make sure the number is odd and has exactly *size* bits
    return num


def get_random_prime(size):
    """ Generate random prime number of specified size

    :param size: bit length of prime to be generated
    :return:
    """
    while True:
        num = get_random_odd(size)
        if miller_rabin_test(num):
            return num


def key_gen(keylength=1024):
    """ Function that generates public and private key-pairs for RSA

    :param keylength: desired size of N = pq - public parameter
    :return: (N, d) - public key and (N, d, e, p, q) - private key
    """
    # generate two different random primes so that their product has given length (approximately)

    while True:
        p_length = keylength // 2
        p = get_random_prime(p_length)
        q = get_random_prime(p_length)
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)
    # according to R.L. Rivest, A. Shamir, and L. Adleman
    # it's enough to take d prime and greater than max(p, q)
    # then gcd(d, phi(n)) = 1
    d_size = random.randint(p_length + 1, keylength - 1)
    d = get_random_prime(d_size)
    _, e = euclidian_extended(d, phi)
    return (n, d), (n, d, e, p, q)


def encrypt(ptext, key):
    """ RSA encryption with public key *key*

    :param ptext: message to be encrypted
    :param key: public key
    :return: ciphertext (integer)
    """
    if isinstance(ptext, bytes):
        ptext = int.from_bytes(ptext, byteorder='big')
    N, d = key
    if ptext >= N or euclidian_extended(ptext, N)[0] != 1:
        raise OverflowError("Message could not be encrypted")
    ctext = fast_exp(ptext, d, N)
    # return int.to_bytes(ctext, byteorder='big', length=ctext.bit_length() // 8 + 1)
    return ctext


def decrypt(ctext, key):
    """ RSA decryption

    :param ctext: message to be decrypted
    :param key: private key (N, d, e, p, q)
    :return: decrypted message (integer)
    """
    if isinstance(ctext, bytearray):
        ctext = int.from_bytes(ctext, byteorder='big')
    N, _, e, _, _ = key
    if ctext >= N or euclidian_extended(ctext, N)[0] != 1:
        raise Exception("Message could not be encrypted")
    ptext = fast_exp(ctext, e, N)
    # return int.to_bytes(ptext, byteorder='big', length=ptext.bit_length() // 8 + 1)
    return ptext

