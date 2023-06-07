"""
Chosen-ciphertext attack on PKCS #1 v1.5
http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
"""
from oracles import PKCS1_v1_5_Oracle
from os import urandom
from Crypto.PublicKey import RSA

#### Added this
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def egcd(a, b):
    """
    Use Euclid's algorithm to find gcd of a and b
    """
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def modinv(a, m):
    """
    Compute modular inverse of a over m
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def divceil(a, b):
    """
    Accurate division with ceil, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: ceil(a / b)
    """
    q, r = divmod(a, b)
    if r:
        return q + 1
    return q


def divfloor(a, b):
    """
    Accurate division with floor, to avoid floating point errors
    :param a: numerator
    :param b: denominator
    :return: floor(a / b)
    """
    q, r = divmod(a, b)
    return q


def merge_intervals(intervals):
    """
    Given a list of intervals, merge them into equivalent non-overlapping intervals
    :param intervals: list of tuples (a, b), where a <= b
    :return: list of tuples (a, b), where a <= b and a_{i+1} > b_i
    """
    intervals.sort(key=lambda x: x[0])

    merged = []
    curr = intervals[0]
    high = intervals[0][1]

    for interval in intervals:
        if interval[0] > high:
            merged.append(curr)
            curr = interval
            high = interval[1]
        else:
            high = max(high, interval[1])
            curr = (curr[0], high)
    merged.append(curr)
    return merged


def blinding(k, key, c, oracle):
    """
    Step 1 of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c: integer smaller than n
    :param oracle: oracle that checks ciphertext conformity
    :return: integers s_0, c_0 s.t. c_0 represents a conforming encryption and c_0 = (c * (s_0) ** e) mod n
    """
    if oracle.query(c.to_bytes(k, byteorder='big')):
        return 1, c
    indx = 0 # Added index for information
    while True:
        indx += 1
        if indx % 200 == 0:
            print(f"{indx}")
        s_0 = urandom(k)
        s_0 = int.from_bytes(s_0, byteorder='big') % key.n
        c_attempt = (c * pow(s_0, key.e, key.n)) % key.n
        if oracle.query(c_attempt.to_bytes(k, byteorder='big')):
            return s_0, c_attempt


def find_min_conforming(k, key, c_0, min_s, oracle):
    """
    Step 2.a and 2.b of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param c_0: integer that represents a conforming ciphertext
    :param min_s: minimal s to run over
    :param oracle: oracle that checks ciphertext conformity
    :return: smallest s >= min_s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    while True:
        # s_0 = int.from_bytes(s_0, byteorder='big') % key.n
        c_attempt = (c_0 * pow(min_s, key.e, key.n)) % key.n
        if oracle.query(c_attempt.to_bytes(k, byteorder='big')):
            return min_s


def search_single_interval(k, key, B, prev_s, a, b, c_0, oracle):
    """
    Step 2.c of the attack
    :param k: length of block in bytes
    :param key: RSA key
    :param B: 2 ** (8 * (k - 2))
    :param prev_s: s value of previous round
    :param a: minimum of interval
    :param b: maximum of interval
    :param c_0: integer that represents a conforming ciphertext
    :param oracle: oracle that checks ciphertext conformity
    :return: s s.t. (c_0 * (s ** e)) mod n represents a conforming ciphertext
    """
    # ?


def narrow_m(key, m_prev, s, B):
    """
    Step 3 of the attack
    :param key: RSA key
    :param m_prev: previous range
    :param s: s value of the current round
    :param B: 2 ** (8 * (k - 2))
    :return: New narrowed-down intervals
    """
    # intervals = []
    # for a, b in m_prev:
        # min_r = ?
        # max_r = ?
        # for r in range(min_r, max_r + 1):
            # start = ?
            # end = ?
            # intervals.append((start, end))

    # return merge_intervals(intervals)


def bleichenbacher_attack(k, key, c, oracle, verbose=False):
    """
    Given an RSA public key and an oracle for conformity of PKCS #1 encryptions, along with a value c, calculate m = (c ** d) mod n
    :param k: length of ciphertext in bytes
    :param key: RSA public key
    :param c: input parameter
    :param oracle: oracle that checks ciphertext conformity
    :return: m s.t. m = (c ** d) mod n
    """
    B = 2 ** (8 * (k - 2))

    c = int.from_bytes(c, byteorder='big')
    s_0, c_0 = blinding(k, key, c, oracle)

    print(f"{s_0=} {c_0=}")

    if verbose:
        print("Blinding complete")

    m = [(2 * B, 3 * B - 1)]

    i = 1
    while True:
        if verbose:
            print("Round ", i)
        if i == 1:
            s = find_min_conforming(k, key, c_0, divceil(key.n, 3 * B), oracle)
        elif len(m) > 1:
            s = find_min_conforming(k, key, c_0, s + 1, oracle)
        else:
            a = m[0][0]
            b = m[0][1]
            s = search_single_interval(k, key, B, s, a, b, c_0, oracle)

        m = narrow_m(key, m, s, B)

        if len(m) == 1 and m[0][0] == m[0][1]:
            # result = ?
            break
        i += 1

    # Test the result
    if pow(result, key.e, key.n) == c:
        return result.to_bytes(k, byteorder='big')
    else:
        return None


if __name__ == "__main__":
    n_length = 1024

    key = RSA.generate(n_length)
    pub_key = key.public_key()
    k = int(n_length / 8)

    oracle = PKCS1_v1_5_Oracle(key)

    # good_m = b'\x00\x02' + 8 * b'\x11' + b'\x00' + (k - 11) * b'\x01'
    # bad_m = b'\x00\x00' + 8 * b'\x11' + b'\x00' + (k - 11) * b'\x01'
    # print(len(good_m))
    c = b'\x00' + (k - 1) * bytes([1])
    cipher = PKCS1_v1_5.new(key)
    signature = pkcs1_15.new(key)

    good_c = cipher.encrypt(b"hello")
    bad_c = signature.sign(SHA256.new(b"hello"))

    # result = bleichenbacher_attack(k, pub_key, good_c, oracle, True)
    # print(result)
    result = bleichenbacher_attack(k, pub_key, bad_c, oracle, True)
    print(result)
    
    result = bleichenbacher_attack(k, pub_key, c, oracle, True)
    print(result)
