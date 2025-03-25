"""
AES full key recovery attack utilizing cache leakage of T-Table access
"""

from softAES import AES
from softAES import _bytes_to_string
from softAESr import AESr

import numpy as np
from hashlib import sha256
import copy

BlockSize = 16
NumTables = 4


def parse_key(k0, k1, k2, k3, key_high):
    """
    Parse the output of guess_key_ttable() and XOR with key_high to give a full round key
    """
    key = np.empty(16, dtype=np.uint8)
    key[0x0] = (k0 >> 12) & 0xf ^ key_high[0x0]
    key[0x5] = (k0 >> 8) & 0xf ^ key_high[0x5]
    key[0xa] = (k0 >> 4) & 0xf ^ key_high[0xa]
    key[0xf] = k0 & 0xf ^ key_high[0xf]

    key[0x4] = (k1 >> 12) & 0xf ^ key_high[0x4]
    key[0x9] = (k1 >> 8) & 0xf ^ key_high[0x9]
    key[0xe] = (k1 >> 4) & 0xf ^ key_high[0xe]
    key[0x3] = k1 & 0xf ^ key_high[0x3]

    key[0x8] = (k2 >> 12) & 0xf ^ key_high[0x8]
    key[0xd] = (k2 >> 8) & 0xf ^ key_high[0xd]
    key[0x2] = (k2 >> 4) & 0xf ^ key_high[0x2]
    key[0x7] = k2 & 0xf ^ key_high[0x7]

    key[0xc] = (k3 >> 12) & 0xf ^ key_high[0xc]
    key[0x1] = (k3 >> 8) & 0xf ^ key_high[0x1]
    key[0x6] = (k3 >> 4) & 0xf ^ key_high[0x6]
    key[0xb] = k3 & 0xf ^ key_high[0xb]

    return _bytes_to_string(key)


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


def simulate_cache_access(plaintexts, key, start_round, end_round):
    """
    Generates an array that holds the top-half nibbles used to access each T-Table over several rounds
    :param plaintexts: list of plaintexts
    :param key: encryption key
    :param start_round: first round to gain traces from
    :param end_round: final round to gain traces from
    :return: accessed_list, where accessed_list[j][i] is a list of the top-half nibbles used to access table i in trace j
    """
    aes = AESr(key, end_round)

    num_traces = len(plaintexts)

    accessed_list = np.empty((num_traces, NumTables), dtype=object)
    for j in range(num_traces):
        for i in range(NumTables):
            accessed_list[j][i] = []

    for j in range(num_traces):
        for r in range(max(start_round, 1), end_round + 1):
            stateround = aes.encrypt_r(plaintexts[j], r, start_round)
            for i in range(NumTables):
                for l in range(int(BlockSize / NumTables)):
                    accessed_list[j][i].append( stateround[i+4*l] & 0xF0 ) #?
                    #table[0] = 0,4,8,12
                    #table[1] = 1,5,9,13
                    #table[2] = 2,6,10,14
                    #table[3] = 3,7,11,15

    # Remove ordering of accesses, so as to not leak in which round each access happened.
    for j in range(num_traces):
        for i in range(NumTables):
            accessed_list[j][i].sort()

    return accessed_list


def find_unaccessed(accessed_list):
    """
    Generates a list of nibbles not used to access T-Tables
    :param accessed_list: accessed_list[i][j] is a list of the top-half nibbles used to access table i in trace j
    :return: unaccessed_list[i][j] is a list of the top-half nibbles not used to access table i in trace j
    """
    num_traces = len(accessed_list)

    unaccessed_list = np.empty((num_traces, NumTables), dtype=object)
    for j in range(num_traces):
        for i in range(NumTables):
            unaccessed_list[j][i] = []

    for j in range(num_traces):
        for i in range(NumTables):
            accessed = np.full(16, False)
            for guess in accessed_list[j][i]:
                accessed[guess >> 4] = True
            for guess in range(16):
                if not accessed[guess]:
                    unaccessed_list[j][i].append(guess << 4)

    return unaccessed_list


def guess_key_high(plaintexts, unaccessed_list):
    """
    Guesses a partial round key, comprised of the top nibble of each byte
    :param plaintexts: list of plaintexts
    :param unaccessed_list: unaccessed_list[i][j] is a list of the top-half nibbles not used to access table i in trace j
    :return: list of guesses for each column
    """
    num_traces = len(plaintexts)
    key_list = np.empty(BlockSize, dtype=object)

    for i in range(NumTables):
        for l in range(int(BlockSize / NumTables)):
            guess_list = np.full(2 ** 4, True)
            for j in range(num_traces):
                for nibble in unaccessed_list[j][i]:
                    guess_list[(plaintexts[j][(i + NumTables * l) % BlockSize] >>4) ^ (nibble>>4)] = False #?
            key_list[(i + NumTables * l) % BlockSize] = [guess << 4 for guess in range(2 ** 4) if guess_list[guess]]

    return key_list


def calc_ttables(l, plaintexts, partial_k0_high):
    """
    Preprocess the results of each T-Table given each plaintext and each bottom key nibble
    :param l: The index corresponding to a set of 4 key bytes
    :param plaintexts: list of plaintexts
    :param partial_k0_high: list holding the upper nibble of each key byte
    :return: 3-dimensional array T-result, where T_result[j][nibble][i] holds the output of Table i for the j'th
        plaintext and bottom k0 nibble nibble
    """
    num_traces = len(plaintexts)
    T_result = np.empty((num_traces, 2 ** 4, NumTables), dtype=np.uint32)

    #?
    tables =[AES.T1,AES.T2,AES.T3,AES.T4]
    for j in range(num_traces):
        for nibble in range(16):
            for i in range(NumTables):
                tmp = partial_k0_high[i]^nibble #= k[(NumTables * l + (i * int(BlockSize / NumTables + 1))) & 0xf]
                tmp ^= plaintexts[j][(NumTables * l + (i * int(BlockSize / NumTables + 1))) & 0xf] #k[] XOR p[]
                T_result[j][nibble][i] = tables[i][tmp]

    return T_result


def find_unviable_candidates(j, T_result, k0_low, viable):
    """
    Find all unviable candidates for upper nibble of k1
    :param j: index of a plaintext
    :param T_result: lookup table of T-Table results
    :param k0_low: candidate for a lower nibble of k0
    :param viable: lookup table for viability of T-Table inputs
    :return: list of (k1_nibble, i), where k1_nibble is an unviable candidate for table i
    """
    k0_0 = k0_low >> 12 & 0xf
    k0_1 = k0_low >> 8 & 0xf
    k0_2 = k0_low >> 4 & 0xf
    k0_3 = k0_low & 0xf

    unviable = []
    #?
    #Col[2][0] = T0[Col[1][0][0]^k[1][0]] ^ ..........
    col_1_l = T_result[j][k0_0][0] ^ T_result[j][k0_1][1] ^ T_result[j][k0_2][2] ^ T_result[j][k0_3][3]
    for i in range(NumTables):
        for t in range(2 ** 4):
            if viable[t][i] == False: #top-half nibbles (as value t) not used to access table i (in trace j)
                #thus for example if i=0 and l=0: (Col[1][0][0]^k[1][0])&0xf0 != t            
                #(k1_nibble =) k[1][0] & 0xf0 != (Col[1][0][0] ^ t) & 0xf0
                #tmp = (bytes.fromhex(hex(col_1_l)[2:]))[i] #The i'th byte will be used for Ti calculation
                tmp = (int(col_1_l).to_bytes(4,byteorder='big'))[i] #type(col_1_l) = numpy.uint32
                unviable_nibble = (tmp>>4) ^ t 
                
                unviable.append((unviable_nibble,i))


    return unviable


def parse_key_candidates(candidates):
    """
    Given a table of candidates for k0 and k1, generate a list of guesses for k_guess
    :param candidates: array such that candidates[k0_low][k1_nibble][i] is True if k0_low and k1_nibble give viable
        inputs to table i for all samples.
    :return: List of guesses for k0_low
    """
    k_guess = []

    for k0_low in range(2 ** 16):
        candidate = True
        for i in range(NumTables):
            exists_valid_k1_nibble = False
            for k1_nibble in range(2 ** 4):
                if candidates[k0_low][k1_nibble][i]:
                    exists_valid_k1_nibble = True
                    break
            if not exists_valid_k1_nibble:
                candidate = False
        if candidate:
            k_guess.append(k0_low)
    return k_guess


def guess_key_ttable(plaintexts, unaccessed_list, key_high, verbose=False):
    """
    Generates the bottom nibbles of a round key using T-Table access traces
    :param plaintexts: list of plaintexts
    :param unaccessed_list: unaccessed_list[i][j] is a list of the top-half nibbles not used to access table i in trace j
    :param key_high: the top nibble of each key byte
    :return: list of possible keys
    """
    num_traces = len(plaintexts)
    k0_guess = np.empty(int(BlockSize / NumTables), dtype=object)

    for l in range(int(BlockSize / NumTables)):
        partial_k0_high = [key_high[(NumTables * l + (i * int(BlockSize / NumTables + 1))) & 0xf] for i in range(NumTables)]
        #partial_k0_high = [key_high[0],key_high[5],key_high[10],key_high[15]] for l=0
        #partial_k0_high = [key_high[4],key_high[9],key_high[14],key_high[3]] for l=1
        #partial_k0_high = [key_high[8],key_high[13],key_high[2],key_high[7]] for l=2
        #partial_k0_high = [key_high[12],key_high[1],key_high[6],key_high[11]] for l=3
        #Same as Column calculation in page 27


        T_result = calc_ttables(l, plaintexts, partial_k0_high)

        candidates = np.full((2 ** 16, 2 ** 4, NumTables), True)

        for j in range(num_traces):
            viable = np.full((2 ** 4, NumTables), True)
            for i in range(NumTables):
                for nibble in unaccessed_list[j][i]:
                    viable[nibble >> 4][i] = False

            for k0_low in range(2 ** 16):
                unviable = find_unviable_candidates(j, T_result, k0_low, viable)
                for k1_nibble, i in unviable:
                    candidates[k0_low][k1_nibble][i] = False

            if verbose:
                print("Trace ", j)
        k0_guess[l] = parse_key_candidates(candidates)

        if verbose:
            print(len(k0_guess[l]), "options for part", l, "of key: ", k0_guess[l])

    key_list = []
    for k0_0 in k0_guess[0]:
        for k0_1 in k0_guess[1]:
            for k0_2 in k0_guess[2]:
                for k0_3 in k0_guess[3]:
                    key_list.append(parse_key(k0_0, k0_1, k0_2, k0_3, key_high))
    return key_list


def  guess_k1_ttable(plaintexts, unaccessed_list, k0, verbose=False):
    """
    Generates k1 using T-Table access traces
    :param plaintexts: list of plaintexts
    :param unaccessed_list: unaccessed_list[i][j] is a list of the top-half nibbles not used to access table i in trace j
    :param k0: first round key
    :return: list of possible keys
    """
    num_traces = len(plaintexts)

    # Calculate the first round of AES on each trace using k0 as a full 128-bit key (utilizing the AES key schedule)
    aes = AESr(k0, 2)

    r1 = np.empty(num_traces, dtype=bytearray)

    #?
    for j in range(num_traces):
       r1[j] = aes.encrypt_r(plaintexts[j], 2, 0,False)
    #

    key_list = guess_key_high(r1, unaccessed_list)

    if verbose:
        print("Number of partial k1 options: ", np.prod([len(x) for x in key_list]))

    k1_high_list = generate_key_options([[]], key_list)
    k1_list = []
    for k1 in k1_high_list:
        key_list = guess_key_ttable(r1, unaccessed_list, k1, verbose)
        k1_list += copy.copy(key_list)
    return k1_list


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

    # Remove duplicate keys
    return list(dict.fromkeys(full_key_list))


def cache_attack(key_len, plaintexts, accessed_list, verbose=False):
    """
    Recover the full encryption key using T-Table access traces
    :param key_len: length of key in bits
    :param plaintexts: list of plaintexts
    :param accessed_list: accessed_list[i][j] is a list of the top-half nibbles used to access table i in trace j
    :return: list of possible keys
    """
    if key_len not in [128, 192, 256]:
        raise Exception("unsupported key length")

    unaccessed_list = find_unaccessed(accessed_list)
    key_list = guess_key_high(plaintexts, unaccessed_list)

    if verbose:
        print("Number of partial key options: ", np.prod([len(x) for x in key_list]))

    k0_high_list = generate_key_options([[]], key_list)
    k0_list = []
    for k0 in k0_high_list:
        key_list = guess_key_ttable(plaintexts, unaccessed_list, k0, verbose)
        if verbose:
            print("Number of k0 options: ", len(key_list))
        k0_list += copy.copy(key_list)

    # Remove duplicate keys
    k0_list = list(dict.fromkeys(k0_list))

    if key_len == 128:
        return k0_list

    k1_list = []
    for k0 in k0_list:
        key_list = guess_k1_ttable(plaintexts, unaccessed_list, k0, verbose)
        if verbose:
            print("Number of k1 options: ", len(key_list))
        k1_list += copy.copy(key_list)

    # Remove duplicate keys
    k1_list = list(dict.fromkeys(k1_list))

    return recover_full_key(key_len, k0_list, k1_list)


def check_test_vectors():
    """
    Checks and prints test vectors on various functions
    """
    num_traces = 15
    plaintext_seed = 0

    key = '00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f'

    # Generate random plaintexts
    plaintexts = np.empty(num_traces, dtype=bytearray)
    for i in range(num_traces):
        sha = sha256()
        sha.update(bytes([plaintext_seed]) + bytes([i]))
        plaintexts[i] = sha.digest()[:BlockSize]

    keyarr = bytes.fromhex(key)

    accessed_list = simulate_cache_access(plaintexts, keyarr, 0, 3)

    if set(accessed_list[0][0]) == {16, 48, 64, 80, 96, 144, 160, 176, 192, 240}:
        print("simulate_cache_access: Functional")
    else:
        print("simulate_cache_access: Not Functional")

    T_result = calc_ttables(0, [b'\x96\xa2\x96\xd2$\xf2\x85\xc6{\xee\x93\xc3\x0f\x8a0\x91'], [0, 80, 160, 240])
    if np.array_equal(T_result[0][0], np.array([999329963, 1316239930, 3277757891, 4025428677])):
        print("calc_ttables: Functional")
    else:
        print("calc_ttables: Not Functional")

    unaccessed_list = find_unaccessed(accessed_list)
    viable = np.full((2 ** 4, NumTables), True)
    for i in range(NumTables):
        for nibble in unaccessed_list[0][i]:
            viable[nibble >> 4][i] = False

    if set(find_unviable_candidates(0, T_result, 0, viable)) == {(2, 0), (5, 0), (7, 0), (8, 0), (11, 0), (13, 0), (4, 1), (5, 1), (6, 1), (8, 1), (9, 1), (10, 1), (13, 1), (6, 2), (7, 2), (8, 2), (9, 2), (14, 2), (0, 3), (1, 3), (3, 3), (5, 3), (6, 3), (11, 3), (13, 3)}:
        print("find_unviable_candidates: Functional")
    else:
        print("find_unviable_candidates: Not Functional")

    key_list = guess_key_high(plaintexts, unaccessed_list)

    k0_high_list = generate_key_options([[]], key_list)
    k0_list = []
    for k0 in k0_high_list:
        key_list = guess_key_ttable(plaintexts, unaccessed_list, k0, True)
        k0_list += copy.copy(key_list)

    # Remove duplicate keys
    k0_list = list(dict.fromkeys(k0_list))

    if set(k0_list) == {b'\x00\x11"3DUfw\x88\x99\xaa\xbb\xcc\xdd\xee\xff'}:
        print("guess_key_ttable: Functional")
    else:
        print("guess_key_ttable: Not Functional")


if __name__ == "__main__":

    num_traces = 15
    plaintext_seed = 0

    key = '00112233445566778899aabbccddeeff101112131415161718191a1b1c1d1e1f'

    # Generate random plaintexts
    plaintexts = np.empty(num_traces, dtype=bytearray)
    for i in range(num_traces):
        sha = sha256()
        sha.update(bytes([plaintext_seed]) + bytes([i]))
        plaintexts[i] = sha.digest()[:BlockSize]

    keyarr = bytes.fromhex(key)

    accessed_list = simulate_cache_access(plaintexts, keyarr, 0, 3)

    keys = cache_attack(len(keyarr) * 8, plaintexts, accessed_list, True)
    for k in keys:
        print(k.hex())
