from Crypto.PublicKey import RSA
from oracles import RSA_CRT


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


class RSA_oracle(RSA_CRT):
    def __init__(self, key):
        self._q_inv = modinv(key.q, key.p)
        self._p_inv = modinv(key.p, key.q)
        super(RSA_oracle, self).__init__(key)

    def dec(self, c):
        """
        Decrypt c using self._dec_mod_p and self._dec_mod_q
        :param c: ciphertext
        :return: c ^ d mod n
        """
        m_p = self._dec_mod_p(c)
        m_q = self._dec_mod_q(c)
        return ((m_p * self._q * self._q_inv) + (m_q * self._p * self._p_inv)) % self.n #?

    def faulty_dec(self, c):
        """
        Decrypt c using self._faulty_dec_mod_p and self._dec_mod_q
        :param c: ciphertext
        :return: faulty c ^ d mod n
        """
        m_p = self._faulty_dec_mod_p(c)
        m_q = self._dec_mod_q(c)
        return ((m_p * self._q * self._q_inv) + (m_q * self._p * self._p_inv)) % self.n #?


def bellcore_attack(rsa):
    """
    Given an RSA decryption oracle that utilizes CRT, factor n
    :param rsa: RSA decryption oracle that may calculate c ^ d mod p incorrectly.
    :return: p, q, where p * q = n
    """
    #?
    c = int.from_bytes(b"chosen ciphertext", byteorder='big') % rsa.n
    q = egcd(rsa.n, rsa.dec(c) - rsa.faulty_dec(c))[0]
    p = divceil(rsa.n, q)

    # Test the output
    if p * q == rsa.n:
        return p, q
    else:
        return None


def main():
    n_length = 1024
    key = RSA.generate(n_length)

    rsa = RSA_oracle(key)
    print(bellcore_attack(rsa))


if __name__ == "__main__":
    main()
