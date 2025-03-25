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
        padding_len = data[-1]
        if padding_len + 1 > len(data):
            return None
        pad = data[-padding_len - 1:]
        for byte in pad:
            if byte != padding_len:
                return None
        return data[:-padding_len - 1]

    def __pad(self, data):
        """
        Pad the data so that the block size is a multiple of block_len
        :param data: input data
        :return: padded data with length an integral multiple of block_len
        """
        padding_len = (self.block_len - ((len(data) + 1) % self.block_len)) % self.block_len
        return data + (padding_len + 1) * bytes([padding_len])

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

    def authenticated_enc(self, data, aad, nonce):
        """
        Authenticated encryption
        :param data: input data
        :param aad: additional associated data
        :param nonce: nonce
        :return: c, the result of authenticated encryption
        """
        tag = self.__auth(aad + data)[:self.mac_len]
        p = self.__pad(data + tag)

        # encrypt with AES-CBC
        c = self.__encrypt(p, nonce)

        return c

    def authenticated_dec(self, c, aad, nonce):
        """
        Authenticated decryption
        :param c: ciphertext
        :param aad: additional associated data
        :param nonce: nonce
        :return: decrypted data if verification succeeds, fail state else.
        """
        # decrypt with AES-CBC
        p = self.__decrypt(c, nonce)

        p = self.__strip_padding(p)

        if p is None:
            return None

        data = p[: -self.mac_len]
        auth_tag = p[-self.mac_len:]

        tag = self.__auth(aad + data)[:self.mac_len]
        if tag == auth_tag:
            return data
        else:
            return None
