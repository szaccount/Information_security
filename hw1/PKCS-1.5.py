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
        # We do not validate that a PS passed from the user is valid,
        # because we understood from the requirements that we should only
        # validate this in the decryption. Also, allowing any PS seems
        # useful for testing the code (mainly testing the parsing).
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
        # 0 and 1 are supported for completness
        # (for public-key decryption, for signatures).
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


def test_PKCS():
    n_length = 4096
    data = b'secret message'

    keys = key_gen(n_length)
    print(f"{keys=}")
    for bt in [0, 1, 2]:
        pkcs = RSA_PKCS_1(bt, *keys)

        ed = pkcs.enc_PKCS_1(data)

        d = pkcs.dec_PKCS_1(ed)
        assert d == data

        ps_length = pkcs.k - 3 - len(data)
        ed = pkcs.enc_PKCS_1(
            data,
            ps=b"\xFF" + b"\x00" * (ps_length - 1)
        )
        # PS creates too short padding.
        d = pkcs.dec_PKCS_1(ed)
        assert pkcs.dec_PKCS_1(ed) is None, f"{bt=}, {d=}"
        if bt == 1:
            ed = pkcs.enc_PKCS_1(
                data,
                ps=b"\xFF" * (ps_length - 1) + b"\x11"
            )
            # PS isn't all FF.
            d = pkcs.dec_PKCS_1(ed)
            assert pkcs.dec_PKCS_1(ed) is None, f"{bt=}, {d=}"

    plaintext = b'secret message'
    k = 512
    e = 65537
    N = 529803473496650627334934380236450455032538356845867691553491639849020589682964569661806668914786691748501223909440437806130300519171586828298121962268772685197715268730599506418427305951668095998130510352088559571822485928424720534612361375852356497302008510795686311570027534324871998131804048048067158391219215834397374614550753080054975740380869344333723986639666726972408351961774595737723510103755897591478782064006433024404674824926915257049065823510895853114117051465791267005214570022565207676946975540919079202803285927930435482863237576476716358046126588244842814128846392765505501229886184424798214719183792612309978074438681049484774595062073242781083130584929367924976241241201949848133354904362186863123979207466314983883935150333821513090384995597450801056275162422595097811002576880023033035473507073665579641395471193307206838723201843100817327381312504465400823105279532849974491693124969639764845868404257704504231343823767219590993648642969980972190983908916050857323732031758745594761101938270879446770619871509546586230494277929415316936030998684752438194647869303216150795519644351385751444674729311984019577596274148528982629765298105137796561742168846498641332037014461096613205081415760217327808411909512047
    p = 29940916181823255768723002402474640761740952397604501778009902918984097049933646769487018741501070211773265218193626320482789226320990637575110133100521115398830393590744456310134428444839693553546623035212981991963648774152139781354550126330621691263754359751466190031615906344009167987915034874337015203232456887546496989414909485110159174129380735224098615902655638463424921127481041988531466148158732441901237020506800428870560387695045645947153859460513288840654882405332238352764525463674141443183302164613536674735639346338441535868209752199435606199238962705383570640595396322522316106796557653957879221134721
    q = 17694965320342718374934712795560082845724579075073189037488526073221142586103685746654807748243531145942441319566583577202750819293565449189215862545184847901623541647788356676995486251185728496418472711305760023206225127020026744250964664091335118176840421124477530234206885939401433572297413741017471864821684509654933459688032561542870197836350185114666963733756469614506801425529711221163822728994144102864842314382495456141074001135314850488157434047967801440315677322989738218521876487092403180374188328981368317648470315575602580880306848943747045194497012637888568908575947279451665960904507607288775923489007
    ps = b'\x9b\xb2\x03/\xa9\xf3\xf0\xc4\xbfV>\xbcBnG{D\rc\xf6\xb7\xe3^R\r\xda^E9\xca \xd21F\x17\xfaK\xbb\xbf%\x03v\xa4\xbd\x8cmx\xe3Aj6\x13_\nA\x85\x04\x9eU1F\xe0\xee\x04N\x97\x90\x1e;k\xe4\xc8\xb5\xa4\xb3\x90\x13k\xc7\xcd\xe7\xc8\x94B\xd0lp6\x0e\xcf\xb5\xa5,Y\xf5\xfez\xf3?\xdc\xeaMY\x8e3\xdf\xddl\t7\xdb\xa6L1\xf6\x1f}\xeb\x1b\xdb\xb9\xe5a\xf8\xf5U\x9a\x97\x14\xc0k\xe9{\xa0\x19\xefi\x99R\xb2\xc2\x9fm\x0e\x08}\xef\x1e(\xaa/\xb6\xf6Z\xaa\x08,\x94\xb4\x98\xc2\xbf\x91\xe0\xf6C\x96\xeby\x17\\lg\xa8\x082\x98\x12\xba\xd6\x04\xd3q\x80x\x05\xb0\x9b\xf9\x08Z\x88m\xff\x85S\x8b\xb1\x1b+\xe3`.\xdc\x17B\rt\xaf\x81\xea\xe1$\xfb-\\f\xf9\x9bF\x83\xbd\xa2\xbaHi\xd5\xac\x8e)F\x08\xee\xf5{/u(%>`\x99VT\xc6\xfb#,\xc5\r{\xe0*\x13\x0c<\x98\x0c\xed3\x94\x8f\x88\x11~\x19\x85\xf8\xd7\x1eR\xd1n\x1f\xb2\xe7!:\xfd\x97JK\xd6\xfdp&\xcf\xd4\xeb* 9\xe4"\xb8\xc4a\xde"\xc52-\xb7\x85\xa8wl3\xe4\xa7#A&Gx\xf4\xda\xc4#\x8bl7g\x8fc\\\x1eqe\xff\x9f\x01\x0e\xe6C\x14\x97\x9f\t\xdb\xaa\xe38\x04\xca\x9dg\xad\x91\x83\x8d\x0b:8h\x80*\x12gx\xd4Y\x0f\x0fP\x14\xf8\xa8\xb3\xad\xb3\xb4\x91O;j\xd1csN\x80$\x03\xa2\x0c\r\xbfO\xcaT\x89\xdf\xa5\xabV\xef\xddX\xe4`\xd8\xd6\xe4\x88e\xab\\\xfb\xf9\xc4\xffG\x18\xf1S\xbaBi(\xf0\x82\x93\xad}b\xf2\x11\xab\xb6\xdcy\xbb\x99kwO\xb2@\x9d\x8a*\x121t\xfc\xafR\x1f\xa2\xac\x98\xcc\xd5\xf1z\x11n\xeelF\xfa\xa5/\'\xf6\x86\xa2\xf9\xf9x\x15:\xc0Z\xcb\xb4\xf13\x8cq\x9c\xa2\xda\xc6f\x18\xf3\xf8\xfbj\x7f_O\x04\x1b'
    ciphertext = b'slq\xe0^a|\xd2u\xd9\xd0\xf6\xbe\xde\xc1E\xc1\x10\xa9\xd4a\x90\xc1th\x8b0\xf0\x94\x1e\x01\xcd."rh\xc1>b\x01\x8e4\xe6v\xa8\x0c\x9e{\xd4wZ4l\xf4\xc3\xfbE\x13DX\x99\xb39\x82\xd3\xb5Sb\xa4\xa1\xbe\xc0\x87\x94\x9e]?\xf0P\xccor\x06~\xfbpO\xb8\x16\xe4\xf9\x1b\r\xa3\xb2L\x1eJ\xd8W\x0eF\xef\x92)"\xf8\x1b\xf5\x0e\xc8\x8d\xc6\xa5\x7f\xfc\x8a\x89\xa8(\xb1\xd6\xdd\xa2U\xfd\x92E!\x8a\xdbq\x8b\xc0[\x94\xfd+\xc7p`\n\xae\xe3\x7f+\x93\xb6]\xd6\xb9(CI\xbcq\x1d\xf2/\xa8\x12\xe3\r\x0f\x94+\xea\xb3\'V\x01\xc3\x1a\x83\xd4\x8aN\xa1>\xea\xeesy\xa1\xd3\xd5\xe6\xfe\x10|\xaa\x10\x1acbt\xf1\xc7\xf7\xcbS\x8b\xc1\xaf\xa3\xba\x01y\xc6\xd2\x1b\xd3\xbdwu\xd10\xc7AS\x1f\xe6b\xb0X\x8e\xd1\xdc\xdb\x0c\xb6\xd2a\xeco\x1a\x88u\r0\x13\xbc\x14-<\xb9\x85F\x8e|\xe1\x02A\xa1\xcd\xbccF\xe0f\xd5\xe9\x8c\xab`4\xf7\xbb\xc5\x91\xcc\x0eP\x98<\t\x807\x1dc#\x94\xd8\x91\n\x9fG\xb3\x92\xa2}\xcf\xf9\xcf?G\xdb\xef\n\x7f\xbde\xb0\x8bM\xd8\xd1ew\xdce\'\xdb\xeb}\x12\xc1%c\xbfB;\xd7\xc0-?\xf06;\x8b\xe2\xe73~\x85\r\xabc\x97\x87\x9a+\xac \xd8k\x7fW\xbe\x12\x89!\x08\xe7\x9f\nM\x02\x7f\x10U\x14\xbf!\xc2\x19\x0ep\x80\xa2v\xf4\xb0t\x7f\x05\xebUJ\xb8_\x08\xf9\xc5\x07\xdd\xe8\xa8s\x8b\xc7)?\xa9m\x98x\x8b\xc5\xd0;\xb1\xc8~\x0c\xe8\x1cU.\x8d\xb77,#\xba\x94\x8d\x0b\x8cC\xf2v\xb5)\xf9e\xc2\xbbn\x04E\x18\x8e\xe4\xa6\xee\xb6\'\x1d5n\x15\x9c6\r\x7f\xdc\xd7\x0f\xe1\xf0\xaa\xa5C*\xd9"n\xc2\xd5)i]7\x1c\xd1\x16\xc2\xe7\xc4\xf8V\xd08\xff\x80Y\xc5\x85j\x03\x9d\xb6\xa5\x82\x14\x80i9\xe3\x8fw-\xa8\x9e%p5\xf2}i\xcaO2y\xd8\xb7\xc0\\\xfd\xb7\xd1'
    bt = 2
    pkcs = RSA_PKCS_1(bt, k, e, N, p, q)
    ed = pkcs.enc_PKCS_1(plaintext, ps=ps)
    assert ed == ciphertext
    d = pkcs.dec_PKCS_1(ed)
    assert d == plaintext
    print("Success")


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