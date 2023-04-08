"""
Python implementation of CBC HMAC authenticated encryption
"""

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac


class AEAD(object):
    """
    Authenticated encryption and decryption
    """
    def __init__(self, block_len, mac_key, enc_key):
        self.block_len = block_len
        self.mac_key = mac_key
        self.enc_key = enc_key

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        raise NotImplementedError("Must override authenticated_enc")


    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        raise NotImplementedError("Must override authenticated_dec")


class AEAD_AES_128_CBC_HMAC_SHA_256(AEAD):
    def __init__(self, *args):
        self.block_len = 16
        self.mac_len = 16
        super(AEAD_AES_128_CBC_HMAC_SHA_256, self).__init__(self.block_len, *args)

    def __strip_padding(self, data):
        """
        Strip all padding from the data
        :param data: input data
        :return: stripped data
        """
        pad_len = data[-1]
        actual_data, padding = data[:-(pad_len + 1)], data[-(pad_len + 1): -1]
        for byte in padding: # TODO verify we check all
            if byte != pad_len:
                raise "Padding is not valid" #TODO verify what to do in this case
        expected_pad_len = self.block_len - ((len(actual_data) + 1) % self.block_len) #TODO maybe extract, also used in __pad
        if expected_pad_len != pad_len:
            print(f"{expected_pad_len=} {pad_len=}")
            raise "Padding is not valid" #TODO verify what to do in this case
        return actual_data


    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """
        pad_len = self.block_len - ((len(data) + 1) % self.block_len)
        print(f"{pad_len=}, {data=}")
        padding = pad_len.to_bytes(1, 'little') * (pad_len + 1)
        return data + padding



    def __auth(self, data):
        """
        Call HMAC_SHA_256
        """
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def __encrypt(self, p, nonce):
        """
        Encrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        encryptor = cipher.encryptor()
        return encryptor.update(p) + encryptor.finalize()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.enc_key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    # TODO, verify need to truncate, we added this function
    def __auth_with_truncate(self, data):
        """
        Returning truncated auth byte string.
        """
        tag = self.__auth(data)
        return tag[:self.mac_len]

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        tag = self.__auth_with_truncate(aad + data)
        print(f"{len(tag)=}")
        padded_data = self.__pad(data + tag)
        return self.__encrypt(padded_data, nonce)

    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """

        plain = self.__decrypt(c, nonce)
        plain_no_pad = self.__strip_padding(plain)
        data, tag = plain_no_pad[:-self.mac_len], plain_no_pad[-self.mac_len:]
        expected_tag = self.__auth_with_truncate(aad + data)
        if tag != expected_tag:
            print(f"{data=} {tag=} {expected_tag=}")
            print(f"{len(tag)=} {len(expected_tag)=}")
            raise "Invalid tag" #TODO check what is the FAIL state in the doc
        return data


if __name__ == "__main__":
    data = b'secret data'
    aad = b'more data'
    mac_key = urandom(16)
    enc_key = urandom(16)
    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    nonce = urandom(16)
    print(f"data = {data}")
    print(f"aad = {aad}")
    print(f"mac_key = {mac_key}")
    print(f"enc_key = {enc_key}")
    print(f"nonce = {nonce}")
    ciphertext = aead.authenticated_enc(data, aad, nonce)
    print(f"ciphertext = {ciphertext}")

    p = aead.authenticated_dec(ciphertext, aad, nonce)
    print(p)
    print(len(data))
    print(len(ciphertext))