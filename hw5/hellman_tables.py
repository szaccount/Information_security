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

    # !!!!!!!!!!!!!!!!!! said maybe need to adjust input rather than output
    def calc(self, x):
        """
        Calculate a modified f
        You are allowed to assume that domain <= (range)^2 and range <= (domain)^2
        :param x: input
        :return: random consistent output
        """
        domain = self.f.domain
        rang = self.f.rang
        
        """
        The function adjusts to the larger output if needed.
        """
        # if domain < rang:
        #     return self.f.calc(x) & (domain - 1)
        #     # return self.f.calc(x & (domain - 1))
        # elif domain > rang:
        #     len_domain = self.f.domain_bytes * 8
        #     len_rang = self.f.rang_bytes * 8
        #     num_flavours = len_domain / len_rang
        #     rv = 0
        #     for i in range(num_flavours):
        #         rv <<= len_rang
        #         rv += self.f.calc((x + i) % domain)
        #     return rv
        # else:
        #     return self.f.calc(x)
        
        # Assume x is the size of rang.
        if domain < rang:
            return self.f.calc(x & (domain - 1))
        elif domain > rang:
            len_domain = self.f.domain_bytes * 8
            len_rang = self.f.rang_bytes * 8
            num_parts = len_domain // len_rang + (len_domain % len_rang > 0)
            rv = x
            for i in range(num_parts - 1):
                rv <<= len_rang
                rv += self.f.calc((x + i) % domain)
            return self.f.calc(rv & (domain - 1))
        else:
            return self.f.calc(x)

    def recover_x(self, x):
        """
        Given a value x returned by Hellman's algorithm over self.calc and y, return x' such that self.f.calc(x') = y
        :param x: x such that self.calc_new(x) = y
        :return: x' such that self.f.calc(x') = y
        """
        domain = self.f.domain
        rang = self.f.rang

        # return x
        if domain < rang:
            return x & (domain - 1)
        elif domain > rang:
            len_domain = self.f.domain_bytes * 8
            len_rang = self.f.rang_bytes * 8
            num_parts = len_domain // len_rang + (len_domain % len_rang > 0)
            rv = x
            for i in range(num_parts - 1):
                rv <<= len_rang
                rv += self.f.calc((x + i) % domain)
            return rv & (domain - 1)
        else:
            return x


def hellman_preprocess(m, t, f_tag):
    """
    Preprocess hellman tables
    :param m: number of chains in each table
    :param t: length of the chains, and the number of tables
    :param f_tag: oracle for a random function
    :return: a list of tables, where each table is a dictionary from the end points to the start points
    """
    # tables = []
    # print("In hellman_preprocess")
    # for i in range(t):
    #     print(f"flavour {i=}")
    #     f_tag_i = lambda x: f_tag.calc((x+i) % f_tag.f.domain)
    #     table = defaultdict(list)
    #     for j in range(m):
    #         # print(f"Wroking on chain {j=}")
    #         # start_point = int.from_bytes(urandom(f_tag.f.domain_bytes), byteorder='big')
    #         start_point = j % f_tag.f.domain
    #         point = start_point
    #         for _ in range(t):
    #             point = f_tag_i(point)
    #         table[point] = start_point
    
    #     tables.append(table)
    #     print(i)
    # return tables

    tables = []
    print("In hellman_preprocess")
    for i in range(t):
        print(f"flavour {i=}")
        f_tag_i = lambda x: f_tag.calc((x+i) % f_tag.f.rang)
        table = defaultdict(list)
        for j in range(m):
            # print(f"Wroking on chain {j=}")
            # start_point = int.from_bytes(urandom(f_tag.f.domain_bytes), byteorder='big')
            start_point = j % f_tag.f.rang
            point = start_point
            for _ in range(t):
                point = f_tag_i(point)
            table[point] = start_point
    
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
    # domain = f_tag.f.domain
    # rang = f_tag.f.rang
    
    # y_tag = y

    # print(f"In hellman_online {domain=} {rang=} {t=} {y=}")
    # if domain < rang:
    #     y_tag = y & (domain - 1)
    # elif domain > rang:
    #     diff_num_bytes = f_tag.f.domain_bytes - f_tag.f.rang_bytes
    #     rand_suffix = int.from_bytes(urandom(diff_num_bytes), byteorder='big')
    #     y_tag << (diff_num_bytes * 8)
    #     y_tag += rand_suffix

    # print(f"{y_tag}")

    # points = [y_tag for _ in range(t)] # t as number of tables

    # for step in range(t): # t as max number of steps
    #     print(f"In {step=}")
    #     for i in range(t): # t as number of tables
    #         print(f"Working on table {i=}")
    #         f_tag_i = lambda x: f_tag.calc((x + i) % f_tag.f.domain)
    #         points[i] = f_tag_i(points[i])
    #         points_i = points[i]
    #         if points_i in tables[i].keys(): # TODO can also do if _ in tables[i], might be faster
    #             print(f"{points_i} is endpoint")
    #             ptr = tables[i][points_i] # init to start point
    #             # !!!!!!!!!!!! tha problem we have here is that y not necessarily in chain if dimain != range
    #             # also it might not be in chain if more than one chain leads to endpoint but we have one start
    #             counter = 0
    #             while counter <= t and f_tag_i(ptr) != y_tag: # TODO maybe need to verify against f_i and not f_tag_i also might be infinite
    #                 # print(f"interation {counter} of searching for origin")
    #                 counter += 1
    #                 ptr = f_tag_i(ptr)
    #             print(f"Found origin")
    #             return (ptr + i) % f_tag.f.domain # flavour correction
    # print("Didn't find origin")
    # return None

    domain = f_tag.f.domain
    rang = f_tag.f.rang
    
    points = [y for _ in range(t)] # t as number of tables

    for step in range(t): # t as max number of steps
        print(f"In {step=}")
        for i in range(t): # t as number of tables
            print(f"Working on table {i=}")
            f_tag_i = lambda x: f_tag.calc((x + i) % f_tag.f.rang)
            points[i] = f_tag_i(points[i])
            points_i = points[i]
            if points_i in tables[i].keys(): # TODO can also do if _ in tables[i], might be faster
                print(f"{points_i} is endpoint")
                ptr = tables[i][points_i] # init to start point
                # !!!!!!!!!!!! tha problem we have here is that y not necessarily in chain if dimain != range
                # also it might not be in chain if more than one chain leads to endpoint but we have one start
                counter = 0
                while counter <= t and f_tag_i(ptr) != y: # TODO maybe need to verify against f_i and not f_tag_i also might be infinite
                    # print(f"interation {counter} of searching for origin")
                    counter += 1
                    ptr = f_tag_i(ptr)
                print(f"Found origin")
                return (ptr + i) % f_tag.f.rang # flavour correction
    print("Didn't find origin")
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

    print("In run_hellman !!!!!!!!!!!!!!!!")
    print(f" before preprocess: {m=} {t=}")
    tables = hellman_preprocess(m, t, f_tag)
    print(f" after preprocess")

    success_count = 0
    for i in range(100):
        print("New y trial")
        y = f.calc(int.from_bytes(urandom(f.domain_bytes), byteorder='big'))
        print(f"before hellman_online {y=}")
        x = hellman_online(tables, t, y, f_tag)
        print(f"after hellman_online {x=}")
        if x is not None:
            x = f_tag.recover_x(x)
            print(f"after recover_x, {x=}")
            if f.calc(x) == y:
                print("success, f.calc(x)==y")
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
    # m = ?
    # t = ?
    m = 2 ** 8
    t = 2 ** 8

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def test_3():
    # The case where domain > range
    key = b'\xa42A\xcf\x0c\xf4\x001\xff\xd7\xaa\x8f\tZ\x11\xdd'
    domain_size = 3
    rang_size = 2
    # m = ?
    # t = ?
    m = 2 ** 8
    t = 2 ** 8

    f = PRF(key, domain_size, rang_size)
    return run_hellman(f, m, t)


def main():
    print("Test 1 success rate:", test_1())
    # print("Test 2 success rate:", test_2())
    # print("Test 3 success rate:", test_3())


if __name__ == "__main__":
    main()
