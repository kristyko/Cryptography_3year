# from Cryptography.AES128.galois import GF8, xtime
from galois import GF8, xtime
from os import urandom

Nb = 4
Nk = 4
Nr = 10
LENGTH = 16


# cyclic right rotation of x (1 byte) by y bits
def _rotr(x, y):
    return ((x >> y) | (x << (8 - y))) & 0xff


# xor of w = [w0, w1, w2, w3], v = [v0, v1, v2, v3], where w_i and v_j are 1 byte
def _xor_words(w, v):
    return [w[i] ^ v[i] for i in range(len(w))]


# ============= S-BOX ==============
# S-box: substitution values for the byte  (needed for SubBytes)
def _get_s_box():
    box = []
    c = GF8(0x63)
    for i in range(2 ** 8):
        el = GF8(i).inv().value
        box.append(c.value ^ el ^ _rotr(el, 4) ^ _rotr(el, 5) ^ _rotr(el, 6) ^ _rotr(el, 7))
    return box


# Inverse S-box: substitution values for the byte  (needed for Inverse SubBytes)
def _get_inv_s_box():
    c = GF8(0x5)
    inv_box = []
    for i in range(2 ** 8):
        el = c + (_rotr(i, 7) ^ _rotr(i, 2) ^ _rotr(i, 5))
        inv_box.append(el.inv().value)
    return inv_box


# obtain S_box and Inv_S_box
_S_BOX = tuple(_get_s_box())
_INV_S_BOX = tuple(_get_inv_s_box())


# ============= EXPANDING KEY ==============
def _key_expansion(cipher_key):
    def _sub_word(w):
        for i in range(4):
            w[i] = _S_BOX[w[i]]

    def rot_word(w):
        return w[1:] + [w[0]]

    assert(len(cipher_key) == LENGTH)
    keys = [[cipher_key[i + j] for j in range(4)] for i in range(0, LENGTH, 4)]
    r_con = [0x01, 0x00, 0x00, 0x00]
    for i in range(1, 11):
        temp = rot_word(keys[-1])
        _sub_word(temp)
        temp = _xor_words(temp, r_con)
        r_con[0] = xtime(r_con[0])
        temp = _xor_words(temp, keys[4 * (i - 1)])
        keys += [temp]
        keys += [_xor_words(keys[-1], keys[4 * (i - 1) + 1])]
        keys += [_xor_words(keys[-1], keys[4 * (i - 1) + 2])]
        keys += [_xor_words(keys[-1], keys[4 * (i - 1) + 3])]
    return keys


# ============= S BYTES ==============
def _sub_bytes(S):
    for i in range(4):
        for j in range(Nb):
            S[i][j] = _S_BOX[S[i][j]]


def _inv_sub_bytes(S):
    for i in range(4):
        for j in range(Nb):
            S[i][j] = _INV_S_BOX[S[i][j]]


# ============= SHIFT ROWS =============
def _shift_rows(S):
    for i in range(1, 4):
        S[i] = S[i][i:] + S[i][:i]


def _inv_shift_rows(S):
    for i in range(1, 4):
        S[i] = S[i][-i:] + S[i][:-i]


# ============= MIX COLUMNS =============
def _mix_columns(S):
    def multiply(column):
        """
        |02 03 01 01| |s[0,c]|
        |01 02 03 01| |s[1,c]|
        |01 01 02 03| |s[2,c]|
        |03 01 01 02| |s[3,c]|
        """
        # for explanation see Sec 4.1.2 in The Design of Rijndael by Joan Daemen and Vincent Rijmen
        # (for 8-bit processors)
        t = column[0] ^ column[1] ^ column[2] ^ column[3]
        u = column[0]
        column[0] ^= t ^ xtime(column[0] ^ column[1])
        column[1] ^= t ^ xtime(column[1] ^ column[2])
        column[2] ^= t ^ xtime(column[2] ^ column[3])
        column[3] ^= t ^ xtime(column[3] ^ u)

        return column

    for i in range(Nb):
        res = multiply([S[j][i] for j in range(4)])
        for j in range(4):
            S[j][i] = res[j]


def _inv_mix_columns(S):
    # for explanation see Sec 4.1.3 in The Design of Rijndael
    for i in range(Nb):
        u = xtime(xtime(S[0][i] ^ S[2][i]))
        v = xtime(xtime(S[1][i] ^ S[3][i]))
        S[0][i] ^= u
        S[1][i] ^= v
        S[2][i] ^= u
        S[3][i] ^= v

    _mix_columns(S)


# ============= ADD ROUND KEY =============
def _add_round_key(cipher_key, S):
    for i in range(Nb):
        for j in range(4):
            S[j][i] = S[j][i] ^ cipher_key[i][j]


class AES:
    """
    AES (Advanced Encryption Standard) - a symmetric block cipher standardized by NIST.
    It has a fixed data block size of 16 bytes. This implementation requires also 16 bytes keys.

    Modes of operation supported with AES (in this implementation):
     - Electronic Code Book (ECB)
     - Cipher-Block Chaining (CBC)
     - Counter Mode (CTR)

    """
    MODES = ['ecb', 'cbc', 'ctr']

    def __init__(self, key, mode='ecb', iv=None, nonce=None):
        self.keys = _key_expansion(key)
        assert mode in self.MODES
        self._mode = mode
        self._iv = iv
        self.nonce = nonce

    @staticmethod
    def pad(text):
        """
        pad message so that its length is a multiple of 128 bits (16 bytes)
        Scheme:
               message => message || 1 || 0..0
                                         ((128 - m - 1) % 128), m - is bit-length of message
        :param text: message to be padded
        :return: padded message
        """
        m = len(text)
        text += (128).to_bytes(1, 'big') + (0).to_bytes((LENGTH - m - 1) % LENGTH, 'big')
        return text

    @staticmethod
    def unpad(text):
        """
        unpad message in regard with the padding scheme, described above
        :param text: message to be unpadded
        :return: unpadded message
        """
        i = 0
        while True:
            i -= 1
            if text[i] == 0x80:
                break
        return text[:i]

    def encode(self, message):
        if self._mode == 'ecb':
            return self._encode_ecb(message)
        elif self._mode == 'cbc':
            return self._encode_cbc(message)
        elif self._mode == 'ctr':
            return self._encode_ctr(message)

    def decode(self, message):
        if self._mode == 'ecb':
            return self._decode_ecb(message)
        elif self._mode == 'cbc':
            return self._decode_cbc(message)
        elif self._mode == 'ctr':
            return self._decode_ctr(message)

    def _encode_block(self, block):
        S = [[block[4 * i + j] for i in range(Nb)] for j in range(4)]
        _add_round_key(self.keys[:Nb], S)
        for i in range(1, Nr):
            _sub_bytes(S)
            _shift_rows(S)
            _mix_columns(S)
            _add_round_key(self.keys[i * Nb:(i + 1) * Nb], S)
        _sub_bytes(S)
        _shift_rows(S)
        _add_round_key(self.keys[Nr * Nb:(Nr + 1) * Nb], S)

        s = bytearray()
        for i in range(Nb):
            for j in range(4):
                s.append(S[j][i])
        return s

    def _decode_block(self, block):
        S = [[block[4 * i + j] for i in range(Nb)] for j in range(4)]
        _add_round_key(self.keys[Nr * Nb:], S)
        for i in range(Nr - 1, 0, -1):
            _inv_shift_rows(S)
            _inv_sub_bytes(S)
            _add_round_key(self.keys[i * Nb:i * Nb + 4], S)
            _inv_mix_columns(S)
        _inv_shift_rows(S)
        _inv_sub_bytes(S)
        _add_round_key(self.keys[0:Nb], S)

        s = bytearray()
        for i in range(Nb):
            for j in range(4):
                s.append(S[j][i])
        return s

    def _encode_ecb(self, p):
        """
        Electronic CodeBook.
        Each block of plaintext is encrypted independently of any other block.

        :param p: plaintext
        :return: ciphertext
        """
        res = b''
        for i in range(0, len(p), LENGTH):
            res += self._encode_block(p[i:i + LENGTH])
        return res

    def _decode_ecb(self, c):
        """
        Each block of ciphertext is decrypted independently of any other block.

        :param c: ciphertext
        :return: plaintext
        """
        res = b''
        for i in range(0, len(c), LENGTH):
            res += self._decode_block(c[i:i + LENGTH])
        return res

    def _encode_cbc(self, p):
        """
        Ciphertext Block Chaining.
        It is a mode of operation where each plaintext block
        gets XOR-ed with the previous ciphertext block prior to encryption.

        if initial vector is None - generate random 16-byte vector

        :param p: plaintext
        :return: ciphertext
        """
        res = b''
        if self._iv is None:
            self._iv = urandom(16)
        C = self._iv
        for i in range(0, len(p), LENGTH):
            block = p[i:i + LENGTH]
            C = self._encode_block(_xor_words(block, C))
            res += C
        return res

    def _decode_cbc(self, c):
        """
        Decryption regarding encryption scheme:
         - decode block
         - XOR result with previous decrypted block

        :param c: ciphertext
        :return: plaintext
        """
        result = b''
        C = self._iv
        for i in range(0, len(c), LENGTH):
            block = c[i:i + LENGTH]
            r = self._decode_block(block)
            result += bytearray(_xor_words(r, C))
            C = block
        return result

    def _encode_ctr(self, p):
        """
        CounTeR mode.
        This mode turns the block cipher into a stream cipher.
        Each byte of plaintext is XOR-ed with a byte taken from a keystream: the result is the ciphertext.
        The keystream is generated by encrypting a sequence of counter blocks with ECB.

        counter block consists of:
         - fixed nonce, set at initialization
           If not - generate random value of size LENGTH / 2 = 8
         - counter (in this implementation always starts with 0)
         CounterBlock = Nonce || Counter
         total size - LENGTH

        :param p: plaintext
        :return: ciphertext
        """
        C = 0
        res = b''
        if self.nonce is None:
            self.nonce = urandom(8)
        assert len(self.nonce) < LENGTH
        c_size = 16 - len(self.nonce)
        for i in range(0, len(p), LENGTH):
            ks = self._encode_block(self.nonce + C.to_bytes(c_size, 'big'))
            res += bytearray(_xor_words(ks, p[i:i + LENGTH]))
            C += 1
        return res

    def _decode_ctr(self, c):
        """
        Basically the same as encryption except with ciphertext

        :param c: ciphertext
        :return: plaintext
        """
        return self._encode_ctr(c)

