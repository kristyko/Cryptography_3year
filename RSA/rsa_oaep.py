"""
    RSAES-OAEP combines the RSAEP and RSADP primitives with the EME-OAEP encoding method.

    RSAES-OAEP can operate on messages of length up to k - 2 * hLen - 2 octets,
    where hLen is the length of the output from the underlying hash function and
    k is the length in octets of the recipient's RSA modulus.

    Here SHA256 is used as hash-function and
    MGF1 is used as mask generation function
"""


from Cryptography.SHA256.sha256 import SHA256 as SHA
from Cryptography.RSA.rsa_studyv import encrypt, decrypt
from os import urandom


hLen = 32    # 256 bits size of the output of hash-function
k = 128      # denotes the length in octets of the RSA modulus N


def i2osp(x, xLen):
    """
    I2OSP converts a nonnegative integer to an octet string of a specified length.

    x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ... + x_1 256 + x_0
    X = X_1 X_2 ... X_xLen, where X_i = x_(xLen-i) for 1 <= i <= xLen

    :param x: number to be converted
    :param xLen: size of an octet string
    :return: X: corresponding octet string of length l
    """
    assert x < 256 ** xLen
    X = b''
    for i in range(xLen - 1, -1, -1):
        X += int.to_bytes((x >> (8 * i)) & 0xff, 1, 'big')
    return X


def os2ip(X):
    """
    OS2IP converts an octet string to a nonnegative integer.

    x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ... + x_1 256 + x_0
    X = X_1 X_2 ... X_xLen, where X_i = x_(xLen-i) for 1 <= i <= xLen

    :param X: octet string to be converted
    :return: x: nonnegative integer
    """
    x = 0
    xLen = len(X)
    for i in range(xLen):
        x += X[xLen - 1 - i] * 256 ** i
    return x


def mgf1(string, length):
    """
    MGF1 is a mask generation function defined in
    the Public Key Cryptography Standard #1 published by RSA Laboratories

    :param string: octet string (sequence of bytes) to be hashed
    :param length: desired size of the output (at most 2 ** 32)
    :return: mask: an octet string of length l or "mask too long"
    """
    assert length <= 2 ** 32 * hLen
    mask = b''
    for counter in range(length // hLen + 1):
        mask += SHA(string + i2osp(counter, 4)).digest()
    return mask[:length]


def _xor(m1, m2):
    n = max(len(m2), len(m1))
    return (int.from_bytes(m1, 'big') ^ int.from_bytes(m2, 'big')).to_bytes(n, 'big')


def _eme_oaep_encoding(message):
    mLen = len(message)
    lHash = SHA(b'').digest()
    ps = (0).to_bytes(k - mLen - 2 * hLen - 2, 'big')
    db = lHash + ps + (1).to_bytes(1, 'big') + message
    seed = urandom(hLen)
    dbMask = mgf1(seed, k - hLen - 1)
    maskedDB = _xor(dbMask, db)
    seedMask = mgf1(maskedDB, hLen)
    maskedSeed = _xor(seed, seedMask)
    return (0).to_bytes(1, 'big') + maskedSeed + maskedDB


def rsaes_oaep_encrypt(key, message):
    """

    :param key: (n, d) - public key for RSA encryption
    :param message: message to padded and then encrypted, an octet string of length mLen,
               where mLen <= k - 2hLen - 2
           (L - optional label whose association with the message is to
            be verified; here it is always an empty string)
    :return: ciphertext, an octet string of length k
    """
    mLen = len(message)
    if mLen > k - 2 * hLen - 2:
        raise OverflowError("Message is too long")
    message_padded = os2ip(_eme_oaep_encoding(message))
    enc = encrypt(message_padded, key)
    return i2osp(enc, k)


def _eme_oaep_decoding(em):
    lHash = SHA(b'').digest()
    Y, maskedSeed, maskedDb = em[0], em[1: 1 + hLen], em[1 + hLen:]
    seedMask = mgf1(maskedDb, hLen)
    seed = _xor(maskedSeed, seedMask)
    dbMask = mgf1(seed, k - hLen - 1)
    db = _xor(maskedDb, dbMask)
    lHash1 = db[:hLen]
    if lHash != lHash1:
        raise Exception('Decryption error')
    i = hLen
    while db[i] == 0:
        i += 1
    if db[i] != 1 or Y != 0:
        raise Exception('Decryption error')
    return db[i+1:]


def rsaes_oaep_decrypt(key, ciphertext):
    """

    :param key: recipient's RSA private key (k denotes the length in
               octets of the RSA modulus n), where k >= 2hLen + 2
    :param ciphertext: ciphertext to be decrypted, an octet string of length k
           (L - optional label whose association with the message is to
            be verified; here it is always an empty string)
    :return: message, an octet string of length mLen, where mLen <= k - 2hLen - 2
    """
    cLen = len(ciphertext)
    if cLen != k or k < 2 * hLen + 2:
        raise ValueError("Decryption Error")
    em = i2osp(decrypt(os2ip(ciphertext), key), k)
    m = _eme_oaep_decoding(em)
    return m
