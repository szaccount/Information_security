"""
An algorithm for cycle detection
"""

from prf import PRF


class MonotonicStack:
    def __init__(self):
        self.stack = []

    def top(self):
        if len(self.stack) == 0:
            return None
        return self.stack[-1]

    def push(self, a):
        if len(self.stack) == 0:
            self.stack.append(a)
            return None

        while self.stack and self.stack[-1] > a:
            self.stack.pop()
        top_before_a = self.top()
        self.stack.append(a)
        return top_before_a


def find_cycle(f, k, start):
    """
    Return a point x, where x is the first point detected by the Nivasch algorithm
    :param f: oracle for a random function
    :param k: the number of stacks to use
    :param start: starting point for the algorithm
    :return: x, where x is a point inside of a cycle
    """
    stacks = [MonotonicStack() for _ in range(k)]
    x = start
    while True:
        current_stack = stacks[x % k]
        if current_stack.push(x) == x:
            return x
        x = f.calc(x)


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
