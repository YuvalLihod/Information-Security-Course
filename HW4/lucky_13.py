from oracles import CBC_HMAC_Timing_Oracle
from CBC_HMAC import AEAD_AES_128_CBC_HMAC_SHA_256
from os import urandom

BLOCK_LEN = 16


def cut_blocks(c, nonce, t):
    """
    Find the final two blocks to send to the timing oracle
    :param c: parameter of the lucky 13 attack
    :param nonce: nonce for c
    :param t: index if block to be recovered
    :return: c_t_prev: the (t - 1)'th block of c
        c_t: the t'th block of c
    """
    c_t = c[t * BLOCK_LEN: (t + 1) * BLOCK_LEN]
    if t == 0:
        c_t_prev = nonce #?
    else:
        c_t_prev = c[(t-1) * BLOCK_LEN: t * BLOCK_LEN] #?

    return c_t_prev, c_t


def lucky_13(c, nonce, t, oracle):
    """
    Recover the lower two bytes of the t'th block of the decryption of c
    :param c: input ciphertext
    :param nonce: nonce for c
    :param t: index of block to recover
    :param oracle: padding timing oracle
    :return: list of candidates for the lower two bytes of the t'th block of c
    """
    candidates = []

    c_t_prev, c_t = cut_blocks(c, nonce, t)
    c_t_prev = int.from_bytes(c_t_prev, byteorder='big')

    for two_bytes in range(2 ** 16):
        #?
        c_t_prev_tmp = c_t_prev ^ two_bytes
        c = bytes(32)+c_t_prev_tmp.to_bytes(BLOCK_LEN, byteorder='big')+c_t
        if oracle.query([c,nonce]) == 4:
            candidates.append((257^two_bytes).to_bytes(2, byteorder='big')) #257 = b'\x01\x01'




    return candidates


def main():
    enc_key = 0x000102030405060708090A0B0C0D0E0F.to_bytes(BLOCK_LEN, byteorder='big')
    mac_key = 0x000102030405060708090A0B0C0D0E0F.to_bytes(BLOCK_LEN, byteorder='big')
    oracle = CBC_HMAC_Timing_Oracle(enc_key)

    aead = AEAD_AES_128_CBC_HMAC_SHA_256(mac_key, enc_key)
    nonce = 0x00112233445566778899AABBCCDDEEFF.to_bytes(BLOCK_LEN, byteorder='big')

    data = 0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F.to_bytes(BLOCK_LEN * 2, byteorder='big')
    aad = b''

    c = aead.authenticated_enc(data, aad, nonce)

    print(lucky_13(c, nonce, 0, oracle))
    print(lucky_13(c, nonce, 1, oracle))
    print(lucky_13(c, nonce, 3, oracle))


if __name__ == "__main__":
    main()
