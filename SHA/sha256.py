import hashlib
import hmac
from primes import extract_constants

MOD = 0xffffffff  # 32-bit word
BITS_IN_WORD = 32


def _rotr(x, y):
    """The rotate right (circular right shift) operation, where x is a 32-bit word
       and n is an integer with 0 ≤ n < 32, is defined by ROTR n (x) =(x >> n) ∨ (x << w - n).
       Example:
           rotr(234, 4) =        10100000000000000000000000001110
           234 = 11101010
           234 >> 4 =                                        1110
           234 << (32 - 4) = 111010100000000000000000000000000000

    """
    # return (((x & 0xffffffff) >> (y & (BITS_IN_WORD-1))) | (x << (BITS_IN_WORD - (y & (BITS_IN_WORD-1))))) & MOD
    return ((x >> y) | (x << (BITS_IN_WORD - y))) & MOD


def _sigma0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _sigma1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ch(x, y, z):
    return (x & y) ^ ((~x) & z)


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _s0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _s1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def _split_to_words(sentence):
    # length of each word is 32 bits
    # each sentence consists of 512 bits => in total 16 words of 32 bits
    return [sum([
        sentence[i + 0] << 24,
        sentence[i + 1] << 16,
        sentence[i + 2] << 8,
        sentence[i + 3] << 0]) for i in range(0, len(sentence), 4)]


def _padding(w):
    """ Pad w according to the standard

    :param w: binary string to be padded
    :return: padded w

        we need to make w of 512 bits
        w => w || 1 || 0..0 || |binary(w)|,
        where number of 0s: 512 - 65 - |binary(w)|  (mod 512)
        and binary(length(w)) takes the last 64 bits
    """

    n = len(w)
    # 128 = 0b10000000
    w += (128).to_bytes(1, 'big') + (0).to_bytes(1, 'big') * ((64 - 9 - n) % 64) + (n * 8).to_bytes(8, 'big')
    return w


class SHA256:
    """ Cryptographic hash-function SHA-256

    The message to be hashed is first
    (1) padded with its length in such a way that the result is a multiple of 512 bits long, and then
    (2) parsed into 512-bit message blocks M_1; M_2; ...; M_n
     The message blocks are processed one at a time: Beginning with a fixed initial hash value H(0),
     sequentially compute H_i = H_(i-1) + C_M(i)(H_(i-1));
     where C is the SHA-256 compression function and + means word-wise mod 2^32 addition.
     H_N is the hash of M
    """

    def __init__(self, message):
        self.message = message
        self.H, self.K = extract_constants()  # initial hash value and other constants

    def update(self, m):
        self.message += m

    def _digest(self):
        message = _padding(self.message)
        hash_v = self.H
        for i in range(0, len(message), 64):
            m = message[i:i + 64]
            words = _split_to_words(m)
            for j in range(16, 64):
                words.append((words[j - 16] + _s0(words[j - 15]) + words[j - 7] + _s1(words[j - 2])) & MOD)

            a, b, c, d, e, f, g, h = hash_v
            for j in range(0, 64):
                t2 = (_sigma0(a) + _maj(a, b, c)) & MOD
                t1 = (h + _sigma1(e) + _ch(e, f, g) + self.K[j] + words[j]) & MOD

                h, g, f, e, d, c, b, a = g, f, e, (d + t1) & MOD, c, b, a, (t2 + t1) & MOD

            hash_v = [(x + y) & MOD for x, y, in zip([a, b, c, d, e, f, g, h], hash_v)]
        return hash_v

    def digest(self):
        """
        Return the digest of the bytes passed to the update() method so far as a bytes object.
        :return:
        """
        hash_v = self._digest()
        res = b''
        for h in hash_v:
            res += h.to_bytes(4, 'big')
        return res

    def hexdigest(self):
        """
        Like digest() except the digest is returned as a string of double length,
        containing only hexadecimal digits.
        :return:
        """
        hash_v = self._digest()
        return ''.join(['0' * (10 - len(hex(h))) + hex(h)[2:] for h in hash_v])


def generate_key(key):
    """ Generates key for AES-128
    :param key: any bytes object
    :return: bytes object of length 128 bit
    """
    return SHA256(key).digest()[:16]


def test():
    message = "abc".encode('utf-8')
    print(hashlib.sha256(message).digest() == SHA256(message).digest())
    print(hashlib.sha256(message).hexdigest() == SHA256(message).hexdigest())

    message = "The quick brown fox jumps over the lazy dog".encode('utf-8')
    print(hashlib.sha256(message).digest() == SHA256(message).digest())
    print(hashlib.sha256(message).hexdigest() == SHA256(message).hexdigest())

    message = "".encode('utf-8')
    print(hashlib.sha256(message).digest() == SHA256(message).digest())
    print(hashlib.sha256(message).hexdigest() == SHA256(message).hexdigest())

    message = ('abc' * 999).encode('utf-8')
    print(hashlib.sha256(message).digest() == SHA256(message).digest())
    print(hashlib.sha256(message).hexdigest() == SHA256(message).hexdigest())

    print(generate_key('meow'.encode('utf-8')))


if __name__ == "__main__":
    test()
