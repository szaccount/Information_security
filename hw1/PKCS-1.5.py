"""
Python implementation of PKCS-1.5 RSA encryption
https://tools.ietf.org/html/rfc2313
"""
from os import urandom
from math import log
from Crypto.Util import number
import sys

# To support recursion in egcd
sys.setrecursionlimit(1500)


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


def key_gen(n_length):
    """
    Generate RSA key
    :param n_length: length of modulus
    :return: k, e, N, p, q
    """
    if n_length % 8:
        raise Exception("n_length must be divisible by 8")

    e = 2 ** 16 + 1

    while True:
        p = number.getPrime(int(n_length / 2), urandom)
        q = number.getPrime(int(n_length / 2), urandom)
        g, x, y = egcd(e, (p - 1) * (q - 1))
        if p != q and g == 1:
            break

    k = int(n_length / 8)
    N = p * q

    return k, e, N, p, q


class RSA(object):
    def __init__(self, k, e, N, p=None, q=None, var=False):
        self.k = k
        self.e = e
        self.N = N
        self.p = p
        self.q = q
        self.var = var
        if self.var:
            print('init vars:', k, N)
        if (p is not None) and (q is not None):
            self.phin = (p - 1) * (q - 1)
            # de = 1 (mod (p-1)(q-1)) and thus is divisible by
            # both p-1, q-1.
            self.d = modinv(self.e, self.phin)
            self.test()
        else:
            self.d = None
        if self.var:
            print(log(N, 2), N)
            if self.d is not None:
                print(hex(self.d))

    def encrypt(self, M):
        return pow(M, self.e, self.N)

    def decrypt(self, C):
        if self.d is None:
            raise Exception('Private key not set')
        return pow(C, self.d, self.N)

    def test(self):
        M = 0x205
        if self.decrypt(self.encrypt(M)) != M:
            raise Exception('Error in RSA decrypt encrypt test')
        if self.var:
            print('RSA decrypt encrypt test success')

    def getN(self):
        return self.N

    def getpqd(self):
        return self.p, self.q, self.d

    def gete(self):
        return self.e


class RSA_PKCS_1(RSA):
    def __init__(self, bt, *args):
        self.bt = bt
        super(RSA_PKCS_1, self).__init__(*args)

    min_pad_size = 11

    def enc_PKCS_1(self, d, ps=None):
        """
        RSA encryption
        """
        if len(d) > self.k - RSA_PKCS_1.min_pad_size:
            raise Exception("byte list too long")

        if self.bt == 0 and d[0] == 0:
            raise Exception("first byte must be nonzero 0 if bt=0")

        if ps is None:
            # PS is at least `RSA_PKCS_1.min_pad_size-3` long, as
            # it was validated that d is short enough.
            ps = self.pad(self.k - 3 - len(d))
        eb = b'\x00' + self.bt.to_bytes(1, byteorder='big') + ps + b'\x00' + d

        x = int.from_bytes(eb, byteorder='big')  # Conversion to integer

        y = self.encrypt(x)

        ed = y.to_bytes(self.k, byteorder='big')
        return ed

    def dec_PKCS_1(self, ed):
        """
        RSA decryption
        """
        if len(ed) != self.k:
            raise Exception("length of ed must be k")

        y = int.from_bytes(ed, byteorder='big')
        if y < 0 or y >= self.N:
            raise Exception("y out of bounds")

        x = self.decrypt(y)

        eb = x.to_bytes(self.k, byteorder='big')

        return self.parse(eb)

    def pad(self, l):
        """
        Generate padding string
        :param l: length of padding string
        :return: padding string
        """
        if self.bt == 0:
            ps = bytes(l)
        elif self.bt == 1:
            ps = l * bytes([0xff])
        elif self.bt == 2:
            added = 0
            ps = b''
            while added < l:
                rand_byte = urandom(1)
                if rand_byte != b'\x00':
                    ps += rand_byte
                    added += 1
        else:
            raise Exception("incompatible block type")
        return ps

    def parse(self, eb):
        """
        Parse encryption block
        :param eb: encryption block
        :return: parsed data
        """
        # Validate that the block is of valid size.
        if len(eb) != self.k:
            return None
        # Validate that the first byte is 00.
        first_byte = eb[0]
        if first_byte != 0:
            return None
        # Validate matching BT.
        # The BT should be only 2 for private-key decryption,
        # 0 and 1 are supported for completness (for public-key decryption).
        bt = eb[1]
        if bt != self.bt:
            return None
        # Strip PS.
        if self.bt == 0:
            d = eb[2:].lstrip(b'\x00')
        elif self.bt == 1:
            zero_and_d = eb[2:].lstrip(b'\xFF')
            # The byte following the PS should be 00.
            if zero_and_d[0] != 0:
                return None
            d = zero_and_d[1:]
        elif self.bt == 2:
            # The byte following the PS should be 00,
            # the PS does not contain zero bytes.
            ps, zero_byte, d = eb[2:].partition(b'\x00')
            if zero_byte != b'\x00':
                return None
        # Validate the PS is at least `RSA_PKCS_1.min_pad_size-3` bytes long.
        padding_length = len(eb) - len(d)
        if padding_length < RSA_PKCS_1.min_pad_size:
            return None
        return d


if __name__ == "__main__":
    n_length = 4096
    data = b'secret message'
    bt = 2

    keys = key_gen(n_length)
    print(keys)

    pkcs = RSA_PKCS_1(bt, *keys)

    ed = pkcs.enc_PKCS_1(data)
    print(ed)

    d = pkcs.dec_PKCS_1(ed)
    print(d)