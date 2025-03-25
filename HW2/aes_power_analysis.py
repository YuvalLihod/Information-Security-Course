"""
AES full key recovery attack utilizing power analysis
"""

from softAES import AES
from softAES import _bytes_to_string
from softAESr import AESr

import numpy as np
from hashlib import sha256
import copy

BlockSize = 16


def hamming_weight(x):
    """
    Calculate Hamming Weight of x
    :param x: x
    :return: hamming weight of x
    """
    hw = 0
    while x != 0:
        hw += x & 1
        x = x >> 1
    return hw


def generate_key_options(keys, option_list):
    """
    Given lists of possible key segments, composes them into a list of keys
    :param keys: [[]]
    :param option_list: list of options for key segments
    :return: list of keys
    """
    if option_list.size == 0:
        return keys

    new_keys = []
    for key in keys:
        for byte in option_list[0]:
            new_keys.append(key + [byte])
    return generate_key_options(new_keys, option_list[1:])


def simulate_power_analysis(plaintexts, key, start_round, end_round):
    """
    Generates an array the holds hamming distances between inputs and outputs of S-boxes
    :param plaintexts: list of plaintexts
    :param key: encryption key
    :param start_round: first round to gain traces from
    :param end_round: final round to gain traces from
    :return: hamming_distances, where hamming_distances[j][r][i] holds the hamming distance corresponding to trace j,
        the r'th round, and byte i
    """
    aes = AESr(key, end_round + 2)

    num_traces = len(plaintexts)

    num_rounds = end_round - max(start_round, 1) + 1
    hamming_distances = np.empty((num_traces, num_rounds, BlockSize), dtype=np.uint8)

    for j in range(num_traces):
        for r in range(max(start_round, 1), end_round + 1):
            stateround = aes.encrypt_r(plaintexts[j], r, start_round)
            for i in range(BlockSize):
                #?
                hamming_distances[j][r-max(start_round, 1)][i] = hamming_weight(aes.S[stateround[i]] ^ stateround[i])

    return hamming_distances


def guess_key_hd(plaintexts, hamming_distances, r):
    """
    Guesses a round key based on hamming distances gleaned from power analysis
    :param plaintexts: list of plaintexts
    :param hamming_distances: hamming_distances[j][r][i] holds the hamming distance corresponding to trace j,
        the r'th round, and byte i
    :param r: round number
    :return: list of guesses for each key byte
    """
    num_traces = len(plaintexts)
    key_list = np.empty(BlockSize, dtype=object)

    for i in range(BlockSize):
        guess_list = np.full(2 ** 8, True)
        #?#
        for guess in range(2 ** 8):
            for j in range(num_traces):
                if hamming_distances[j][r][i] != hamming_weight(AES.S[plaintexts[j][i]^guess] ^ (plaintexts[j][i]^guess)):
                    guess_list[guess] = False
                    break
        #

        key_list[i] = [guess for guess in range(2 ** 8) if guess_list[guess]]

    return key_list


def guess_k1_hd(plaintexts, hamming_distances, k0):
    """
    Guess k1 based on hamming distances gleaned from power analysis
    :param plaintexts: list of plaintexts
    :param hamming_distances: hamming_distances[j][r][i] holds the hamming distance corresponding to trace j,
        the r'th round, and byte i
    :param k0: first round key
    :return: list of guesses for each key byte
    """
    num_traces = len(plaintexts)

    # Calculate the first round of AES on each trace using k0 as a full 128-bit key (utilizing the AES key schedule)
    aes = AESr(k0, 2)

    r1 = np.empty(num_traces, dtype=bytearray)
    #?
    for j in range(num_traces):
       r1[j] = aes.encrypt_r(plaintexts[j], 2, 0,False)
    #
    return guess_key_hd(r1, hamming_distances, 1)


def recover_full_key(key_len, k0_list, k1_list):
    """
    Given candidates for first and second round keys, generate a list of candidates for the full round key
    :param key_len: length of key in bits
    :param k0_list: list of candidates for k0
    :param k1_list: list of candidates for k1
    :return: list of candidates for the full key
    """
    full_key_list = []

    #?
    a = (key_len - 128)//8 #how many bytes should i add to the first 16 bytes of the key
    for k0 in k0_list:
        for k1 in k1_list:
            full_key_list.append(k0+k1[:a])
    #
    # Remove duplicate keys
    return list(dict.fromkeys(full_key_list))


def power_analysis_attack(key_len, plaintexts, hamming_distances, verbose=False):
    """
    Recover the full encryption key using hamming distances between inputs and outputs of sboxes
    :param key_len: length of key in bits
    :param plaintexts: list of plaintexts
    :param hamming_distances: hamming_distances[j][r][i] holds the hamming distance corresponding to trace j, round r,
        and byte i
    :return: list of possible keys
    """
    if key_len not in [128, 192, 256]:
        raise Exception("unsupported key length")

    key_list = guess_key_hd(plaintexts, hamming_distances, 0)

    if verbose:
        print("Number of k0 options: ", np.prod([len(x) for x in key_list]))

    k0_list = generate_key_options([[]], key_list)

    for i in range(len(k0_list)):
        k0_list[i] = _bytes_to_string(k0_list[i])

    # Remove duplicate keys
    k0_list = list(dict.fromkeys(k0_list))

    if key_len == 128:
        return k0_list

    k1_list = []
    for k0 in k0_list:
        key_list = guess_k1_hd(plaintexts, hamming_distances, k0)
        if verbose:
            print("Number of k1 options: ", np.prod([len(x) for x in key_list]))
        k1_list += copy.copy(generate_key_options([[]], key_list))

    for i in range(len(k1_list)):
        k1_list[i] = _bytes_to_string(k1_list[i])

    # Remove duplicate keys
    k1_list = list(dict.fromkeys(k1_list))

    return recover_full_key(key_len, k0_list, k1_list)


def check_test_vectors():
    """
    Checks and prints test vectors on various functions
    """
    num_traces = 10
    plaintext_seed = 0

    key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'

    # Generate random plaintexts
    plaintexts = np.empty(num_traces, dtype=bytearray)
    for i in range(num_traces):
        sha = sha256()
        sha.update(bytes([plaintext_seed]) + bytes([i]))
        plaintexts[i] = sha.digest()[:BlockSize]

    keyarr = bytes.fromhex(key)

    hamming_distances = simulate_power_analysis(plaintexts, keyarr, 0, 2)
    if np.array_equal(hamming_distances[0], np.array([[2, 4, 5, 7, 5, 6, 6, 5, 6, 5, 6, 1, 4, 2, 3, 4], [4, 6, 3, 3, 4, 3, 3, 6, 4, 2, 3, 4, 5, 2, 6, 6]])):
        print("simulate_power_analysis: Functional")
    else:
        print("simulate_power_analysis: Not Functional")

    key_list = guess_key_hd(plaintexts, hamming_distances, 0)

    k0_list = generate_key_options([[]], key_list)

    for i in range(len(k0_list)):
        k0_list[i] = _bytes_to_string(k0_list[i])

    # Remove duplicate keys
    k0_list = list(dict.fromkeys(k0_list))

    if set(k0_list) == {b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f'}:
        print("guess_key_hd: Functional")
    else:
        print("guess_key_hd: Not Functional")


if __name__ == "__main__":

    num_traces = 10
    plaintext_seed = 0

    key = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'

    # Generate random plaintexts
    plaintexts = np.empty(num_traces, dtype=bytearray)
    for i in range(num_traces):
        sha = sha256()
        sha.update(bytes([plaintext_seed]) + bytes([i]))
        plaintexts[i] = sha.digest()[:BlockSize]

    keyarr = bytes.fromhex(key)

    hamming_distances = simulate_power_analysis(plaintexts, keyarr, 0, 2)

    keys = power_analysis_attack(len(keyarr) * 8, plaintexts, hamming_distances, True)
    for k in keys:
        print(k.hex())
