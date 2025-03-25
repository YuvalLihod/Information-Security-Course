"""
An algorithm for a time-memory tradeoff
"""

from prf import PRF
from os import urandom
from collections import defaultdict


class ModifiedPRF(object):
    def __init__(self, f):
        """
        Modifies an expanding or compressing PRF to work with hellman's algorithm
        :param f: oracle for a random function
        """
        self.f = f

    def calc(self, x):
        """
        Calculate a modified f
        You are allowed to assume that domain <= (range)^2 and range <= (domain)^2
        :param x: input
        :return: random consistent output
        """
        domain = self.f.domain
        rang = self.f.rang

        if domain < rang:
            return self.f.calc(x) >> ((self.f.rang_bytes - self.f.domain_bytes)*8) #?
        elif domain > rang:
            #?
            ans = (self.f.calc(x % domain) << (self.f.rang_bytes*8)) | self.f.calc((x + 1) % domain) #2rang_bytes >= domain_bytes
            #now ans maybe not in domain
            tmp = ((2*self.f.rang_bytes - self.f.domain_bytes)*8)
            return ans>>tmp
        else:
            return self.f.calc(x) #?

    def recover_x(self, x):
        """
        Given a value x returned by Hellman's algorithm over self.calc and y, return x' such that self.f.calc(x') = y
        :param x: x such that self.calc_new(x) = y
        :return: x' such that self.f.calc(x') = y
        """
        domain = self.f.domain
        rang = self.f.rang

        if domain < rang:
            return x << ((self.f.rang_bytes - self.f.domain_bytes)*8) #? TODO, it's just a guess
        elif domain > rang:
            return x#? TODO
        else:
            return x #?


def hellman_preprocess(m, t, f_tag):
    """
    Preprocess hellman tables
    :param m: number of chains in each table
    :param t: length of the chains, and the number of tables
    :param f_tag: oracle for a random function
    :return: a list of tables, where each table is a dictionary from the end points to the start points
    """
    tables = []
    for i in range(t):
        table = defaultdict(list)

        #?
        for _ in range(m): #for each chain
            startpoint = int.from_bytes(urandom(f_tag.f.domain_bytes), byteorder='big')
            endpoint = startpoint
            for _ in range(t): #length of the chain
                endpoint = f_tag.calc((endpoint+i)% f_tag.f.domain)
            table[endpoint].append(startpoint)
        #
        tables.append(table)
        print(i)
    return tables


def hellman_online(tables, t, y, f_tag):
    """
    Find x such that f(x)=y
    :param tables: preprocessed tables
    :param t: length of the chains, and the number of tables
    :param y: input
    :param f_tag: modified oracle for a random function
    :return: x such that f(x)=y if the attack succeeded, else None
    """
    #?
    for i in range(t): # for each table
        table = tables[i]
        endpoint = y
        for _ in range(t): #apply f() at most the length of the chain +1 times
            if endpoint in table:
                for startpoint in table[endpoint]:
                    current_point = startpoint
                    for _ in range(t):  #apply f() at most the length of the chain times
                        if f_tag.calc((current_point+i)% f_tag.f.domain) == y:
                            return (current_point+i)% f_tag.f.domain
                        current_point = f_tag.calc((current_point+i)% f_tag.f.domain)
            endpoint = f_tag.calc((endpoint+i)% f_tag.f.domain)
    return None


def run_hellman(f, m, t):
    """
    Run the Hellman algorithm to reverse f
    :param f: oracle for a random function
    :param m: number of chains in each table
    :param t: length of the chains, and the number of tables
    :return: the success rate of the algorithm over 100 inputs
    """
    f_tag = ModifiedPRF(f)

    tables = hellman_preprocess(m, t, f_tag)

    success_count = 0
    for i in range(100):
        y = f.calc(int.from_bytes(urandom(f.domain_bytes), byteorder='big'))
        x = hellman_online(tables, t, y, f_tag)
        if x is not None:
            x = f_tag.recover_x(x)
            if f.calc(x) == y:
                success_count += 1
    return success_count


def test_1():
    # The case where domain = range
    key = b'j\xb1\xd5\xfa\x92\x11X\x12\x00\xde3\xae\x16L8['
    block_size = 3
    m = 2 ** 8
    t = 2 ** 8

    f = PRF(key, block_size)
    return run_hellman(f, m, t)


def test_2():
    # The case where domain < range
    key = b'8{8H\x00\xe5\xa6\xc7BTs=\xba\xd5\x18\xe6'
    domain_size = 2
    rang_size = 3
    #N= 2**16=t*t*m
    #M=t*m
    #T=t**2
    #N^2=T*(M^2)
    m = 2 ** 6
    t = 2 ** 5

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def test_3():
    # The case where domain > range
    key = b'\xa42A\xcf\x0c\xf4\x001\xff\xd7\xaa\x8f\tZ\x11\xdd'
    domain_size = 3
    rang_size = 2
    #N = 2**24
    m = 2 ** 8
    t = 2 ** 8

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def main():
    print("Test 1 success rate:", test_1())
    print("Test 2 success rate:", test_2())
    print("Test 3 success rate:", test_3())


if __name__ == "__main__":
    main()
