import math


def sieve_of_Eratosthenes(n):
    """ Finds all primes from 0 to n using Sieve of Eratosthenes algorithm

    :param n: upper bound for primes to be looked for
    :return: primes: list of primes
    """
    lst_of_numbers = [True] * n
    lst_of_numbers[0], lst_of_numbers[1] = False, False
    for i in range(int(math.sqrt(n)) + 1):
        if lst_of_numbers[i]:
            for j in range(i ** 2, n, i):
                lst_of_numbers[j] = False

    primes = []
    for i in range(len(lst_of_numbers)):
        if lst_of_numbers[i]:
            primes.append(i)
    return primes


def float2bin(b: float):
    """ Convert fractional part of a float number to a binary string

    :param b float number
    :return: string - binary representation of b
    """
    b = b - int(b)
    res = ''
    coef = 1 / 2
    while b > 0 and len(res) < 32:
        if b > coef:
            b -= coef
            res += '1'
        else:
            res += '0'
        coef /= 2
    return res


# put all required constants to a specific file
# (I know this is not the best choice)
def extract_constants():
    # first we need to find enough prime numbers
    prime_list = sieve_of_Eratosthenes(320)

    H = [int(float2bin(math.sqrt(n)), 2) for n in prime_list[:8]]
    K = [int(float2bin(math.pow(n, 1 / 3)), 2) for n in prime_list[:64]]
    return H, K

