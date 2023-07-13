"""
An algorithm for cycle detection
"""

from prf import PRF


class MonotonicStack:
    """
    A stack which is guaranteed to be non-decreasing monotonic
    (i.e, the top of the stack is the biggest value).
    Pushing a value to the stack pops all the bigger values.
    """
    def __init__(self):
        self._stack = []

    def top(self):
        """
        Returns the top of the stack, None if the stack is empty.
        """
        if len(self._stack) == 0:
            return None
        return self._stack[-1]

    def push(self, a):
        """
        Push a new value `a`, and pop all the values bigger than `a`.
        Returns the biggest value after `a` (i.e, the value a is pushed on top,
        this is None if `a` is the only value in the stack).
        """
        if len(self._stack) == 0:
            self._stack.append(a)
            return None

        while self._stack and self._stack[-1] > a:
            self._stack.pop()
        top_before_a = self.top()
        self._stack.append(a)
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
