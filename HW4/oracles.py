"""
Oracles for chosen-ciphertext attacks on PKCS #1
"""
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Oracle(object):
    def __init__(self):
        pass

    def query(self, input):
        raise NotImplementedError("Must override query")


class CBC_HMAC_Timing_Oracle(Oracle):
    """
    Timing padding oracle for CBC-HMAC
    """
    def __init__(self, key):
        self.block_len = 16
        self.many_calls = 5
        self.few_calls = 4
        self.key = key
        super(Oracle, self).__init__()

    def __decrypt(self, c, nonce):
        """
        Decrypt using AES_128_CBC
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(c) + decryptor.finalize()

    def __find_padding_len(self, data):
        """
        Returns the padding length if the padding is valid, and None if the padding is invalid
        :param data: input data
        :return: padding length if padding is valid, None if padding is invalid
        """
        padding_len = data[-1]
        if padding_len + 1 > len(data):
            return None
        pad = data[-padding_len - 1:]
        for byte in pad:
            if byte != padding_len:
                return None
        return padding_len

    def query(self, args):
        """
        Checks if input is a conforming encryption
        :param c: 4 blocks to be decrypted
        :param nonce: Nonce value for encryption - with overwhelming probability has no effect on the oracle
        :return: The number of calls to the hash function during authentication
        """
        c = args[0]
        nonce = args[1]
        if len(c) != self.block_len * 4:
            raise ValueError("The timing oracle only accepts ciphertexts of length 4 blocks")
        if len(nonce) != self.block_len:
            raise ValueError("The nonce must be of length 1 block")

        data = self.__decrypt(c, nonce)
        padding_len = self.__find_padding_len(data)
        if padding_len is None or padding_len == 0:
            return self.many_calls
        return self.few_calls


class RSA_CRT():
    def __init__(self, key):
        self.e = key.e
        self.n = key.n
        self._p = key.p
        self._q = key.q
        self._d = key.d

    def _dec_mod_p(self, c):
        """
        Decrypts c modulo p
        :param c: ciphertext
        :return: c^d mod p
        """
        return pow(c, self._d, self._p)

    def _dec_mod_q(self, c):
        """
        Decrypts c modulo q
        :param c: ciphertext
        :return: c^d mod q
        """
        return pow(c, self._d, self._q)

    def _faulty_dec_mod_p(self, c):
        """
        Incorrectly calculates c modulo p
        :param c: ciphertext
        :return: an incorrect calculation
        """
        return pow(c - 5, self._d + 2, self._p)


def main():
    key = urandom(16)
    oracle = CBC_HMAC_Timing_Oracle(key)

    data = (4 * 16 * bytes([0xa]))[:-1] + b"\x05"
    nonce = urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(nonce))
    encryptor = cipher.encryptor()
    c = encryptor.update(data) + encryptor.finalize()

    nonce = urandom(16)
    print(oracle.query((c, nonce)))


if __name__ == "__main__":
    main()
