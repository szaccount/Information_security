"""
An algorithm for collision detection
"""

from prf import PRF


def find_collision(f, start):
    """
    :param f: oracle for a random function
    :param start: starting point
    :return: x_0, x_1 such that x_0 != x_1 and f(x_0) = f(x_1)
    """
    # Find meeting point.
    slow, fast = start, start
    while True:
        slow = f.calc(slow)
        fast = f.calc(f.calc(fast))
        if slow == fast:
            break

    # Backtrack to start of loop.
    x_0, x_1 = start, slow
    next_x_0, next_x_1 = f.calc(x_0), f.calc(x_1)
    while next_x_0 != next_x_1:
        x_0, x_1 = next_x_0, next_x_1
        next_x_0, next_x_1 = f.calc(x_0), f.calc(x_1)

    return x_0, x_1


def main():
    key = b'\xde\xa4\xf3l\x99~\x13\xed\xf5\x16\xe4#\xc1\xa4\xef\x04'
    block_size = 4
    f = PRF(key, block_size)
    start = 0
    while True:
        x_0, x_1 = find_collision(f, start)
        print(x_0, x_1)
        if x_0 != x_1 and f.calc(x_0) == f.calc(x_1):
            print("Success")
            break
        else:
            print("Fail")
            # What needs to be modified here so that the attack eventually succeeds?
            start += 1


if __name__ == "__main__":
    main()
