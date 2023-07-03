"""
An algorithm for cycle detection
"""

from prf import PRF


def find_cycle(f, k, start):
    """
    Return a point x, where x is the first point detected by the Nivasch algorithm
    :param f: oracle for a random function
    :param k: the number of stacks to use
    :param start: starting point for the algorithm
    :return: x, where x is a point inside of a cycle
    """
    ?


def main():
    key = b'\xf7\xf2&\x1cam\x8fN|9\xa1\x00N\xd3@"'
    block_size = 4
    f = PRF(key, block_size)
    start = 0
    k = 100

    x = find_cycle(f, k, start)

    # test vector
    if x == 8391269:
        print("Success")
    else:
        print("Fail")


if __name__ == "__main__":
    main()
