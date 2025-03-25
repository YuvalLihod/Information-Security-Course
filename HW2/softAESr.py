__author__ = 'eyalro'
from softAES import *
from softAES import _compact_word
from softAES import _bytes_to_string
import copy
import array


class AESr(AES):
    def __init__(self, key, rounds):
        super(AESr, self).__init__(key)
        self._Ke = self._Ke[0:rounds+1]
        self._Kd = self._Kd[-(rounds+1):]
        # Remove XOR of key in last round, makes it easier to work with
        self.final_round_key = self._Ke[-1]
        self._Ke[-1] = [0] * 4
        self._Kd[0] = [0] * 4

    def encrypt_r(self, plaintext, end_round, start_round=0, xorlastroundkey=True):
        """
        Encrypt a block of plain text using the AES block cipher.
        """

        if len(plaintext) != 16:
            print('plaintext len', len(plaintext))
            raise ValueError('wrong block length')

        if end_round >= len(self._Ke):
            raise Exception("not enough key for partial encryption")

        (s1, s2, s3) = [1, 2, 3]
        a = [0, 0, 0, 0]

        if start_round == 0:
            # Convert plaintext to (ints ^ key)
            t = [(_compact_word(plaintext[4 * i:4 * i + 4]) ^ self._Ke[0][i]) for i in range(0, 4)]
            first_round = 1
        else:
            # If we begin from partial encryption then no key is XORed at the beginning
            t = [(_compact_word(plaintext[4 * i:4 * i + 4])) for i in range(0, 4)]
            first_round = start_round

        # Apply round transforms
        for r in range(first_round, end_round):
            for i in range(0, 4):
                a[i] = (self.T1[(t[ i          ] >> 24) & 0xFF] ^
                        self.T2[(t[(i + s1) % 4] >> 16) & 0xFF] ^
                        self.T3[(t[(i + s2) % 4] >>  8) & 0xFF] ^
                        self.T4[ t[(i + s3) % 4]        & 0xFF] ^
                        self._Ke[r][i])
            t = copy.copy(a)

        # The last round is special
        result = []

        if not xorlastroundkey:
            for i in range(0, 4):
                t[i] = t[i] ^ self._Ke[end_round - 1][i]

        for i in range(0, 4):
            result.append((t[i] >> 24) & 0xFF)
            result.append((t[i] >> 16) & 0xFF)
            result.append((t[i] >> 8) & 0xFF)
            result.append(t[i]        & 0xFF)

        return result

    def encrypt_raw_r(self, plaintext, rounds):
        plaintext_arr = array.array('B', plaintext)
        res_array = self.encrypt_r(plaintext_arr, rounds)
        return "".join(map(chr, res_array))

    def get_round_key(self, round):
        return self._Ke[round]

    def get_round_key_bytes(self, round):
        byte_list = []
        for i in range(4):
            word = self._Ke[round][i]
            byte_list.append((word >> 24) & 0xff)
            byte_list.append((word >> 16) & 0xff)
            byte_list.append((word >> 8) & 0xff)
            byte_list.append((word >> 0) & 0xff)
        return byte_list

    def get_round_key_byte(self, round, byte):
        word = int(byte / 4)
        round_key = self.get_round_key(round)
        keyword = round_key[word]
        keybyte = (keyword >> ((3-byte % 4) * 8)) & 0xff
        return keybyte


if __name__ == '__main__':
    p = '00112233445566778899aabbccddeeff'
    key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
    c = '8ea2b7ca516745bfeafc49904b496089'
    r1 = '4f63760643e0aa85efa7213201a4e705'
    r2 = '1859fbc28a1c00a078ed8aadc42f6109'
    r3 = '975c66c1cb9f3fa8a93a28df8ee10f63'

    keyarr = bytes.fromhex(key)
    parr = bytes.fromhex(p)

    # Various tests:
    print(len(keyarr), keyarr)
    print(len(parr), parr)
    aes = AESr(keyarr, 5)

    r5calc = aes.encrypt(parr)

    pcalc = aes.decrypt(r5calc)
    r1calc = aes.encrypt_r(parr, 1)
    r2calc = aes.encrypt_r(parr, 2)
    r3calc = aes.encrypt_r(parr, 3)
    print(_bytes_to_string(r5calc).hex(), 'r5calc')

    print(_bytes_to_string(pcalc).hex(), 'pcalc')
    print(_bytes_to_string(r1calc).hex(), 'r1calc')
    print(_bytes_to_string(r2calc).hex(), 'r2calc')
    print(_bytes_to_string(r3calc).hex(), 'r3calc')
