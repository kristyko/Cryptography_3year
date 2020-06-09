import hashlib
import hmac
from sha256 import SHA256


BLOCK_SIZE = 64
OUTPUT = 32


class HMAC_sha256:
    """ HMAC (Keyed-Hashing for Message Authentication)

    It's a message authentication code obtained by running a cryptographic hash function (SHA-256 in this case)

    HMAC(K, m) = H((K' ^ opad) || H(K' ^ ipad) || m), where
        K' = H(K) if K is larger than block size, K - otherwise
        K - secret key
        m - message to be authenticated
        H = cryptographic hash-function (SHA-256)
        || - concatenation, ^ - bitwise xor
        opad - the block-sized outer padding, consisting of repeated bytes valued 0x5c
        ipad - the block-sized inner padding, consisting of repeated bytes valued 0x36

    """
    def __init__(self, key, message):
        self.key = key
        self.message = message

    def update(self, m):
        self.message += m

    def _digest(self):
        ipad = (0x36).to_bytes(1, 'big') * BLOCK_SIZE
        opad = (0x5c).to_bytes(1, 'big') * BLOCK_SIZE
        if len(self.key) > BLOCK_SIZE:
            temp = SHA256(self.key).digest()
            K = temp + (0).to_bytes(BLOCK_SIZE - OUTPUT, 'big')
        elif (len(self.key)) < BLOCK_SIZE:
            K = self.key + (0).to_bytes(BLOCK_SIZE - len(self.key), 'big')
        else:
            K = self.key
        s_i = bytearray([k ^ i for k, i in zip(K, ipad)])
        s_0 = bytearray([k ^ o for k, o in zip(K, opad)])
        return SHA256(s_0 + SHA256(s_i + self.message).digest())

    def digest(self):
        return self._digest().digest()

    def hexdigest(self):
        return self._digest().hexdigest()


def message_authentification(message, key, hmac_v):
    """ If the receiver gets a message and wants to know whether it had not been corrupted
        it is enough for him to compute hmac value of the message with the common key and
        compare it to the received hmac value of the original value message

    :param message: received message, we want to check its integrity
    :param key: secret key, known to both the sender and receiver
    :param hmac_v: hmac value of the original message
    :return: True if the message is unchanged, False - otherwise
    """
    return HMAC_sha256(key, message).digest() == hmac_v


def test_hmac():
    secret = 'key'.encode('utf-8')
    msg = ("The quick brown fox jumps over the lazy dog" * 100).encode('utf-8')
    a = HMAC_sha256(secret, msg)
    print(a.digest() == hmac.new(secret, msg, digestmod=hashlib.sha256).digest())
    print(a.hexdigest() == hmac.new(secret, msg, digestmod=hashlib.sha256).hexdigest())


if __name__ == "__main__":
    test_hmac()
