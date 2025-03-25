from Crypto.Cipher import AES


class PRF(object):
    def __init__(self, key, domain_bytes, rang_bytes=None):
        """
        Creates a new PRF object
        :param key: AES key
        :param domain_bytes: domain of the PRF in bytes
        :param rang_bytes: range of the PRF in bytes. If left empty equal to the domain
        """
        self.domain_bytes = domain_bytes
        self.domain = 2 ** (domain_bytes * 8)
        if rang_bytes:
            self.rang = 2 ** (rang_bytes * 8)
            self.rang_bytes = rang_bytes
        else:
            self.rang = self.domain
            self.rang_bytes = domain_bytes
        self.cipher = AES.new(key, AES.MODE_ECB)

    def calc(self, x):
        """
        A pseudorandom function
        :param x: input
        :return: random consistent output
        """
        x = x & (self.domain - 1)
        x = x.to_bytes(16, byteorder='big')
        return int.from_bytes(self.cipher.encrypt(x), byteorder='big') & (self.rang - 1)
