import random

from gigue.helpers import align
from gigue.helpers import int_to_bytes32
from gigue.helpers import int_to_bytes64


def raise_no_strategy_error(generation_strategy):
    raise ValueError(f"No generation strategy named '{generation_strategy}'.")


class Dataminer:
    @staticmethod
    def mine_random(*args, **kwargs):
        return random.randbytes(8)

    @staticmethod
    def mine_iterative32(i, *args, **kwargs):
        i = min(0xFFFF, i)
        return int_to_bytes32(i // 4) + int_to_bytes32(i // 4 + 1)

    @staticmethod
    def mine_iterative64(i):
        i = min(0xFFFFFFFF, i)
        return int_to_bytes64(i // 8)

    @staticmethod
    def generate_data(generation_strategy, size):
        size = align(size, 8)
        bin_data = b""
        if not hasattr(Dataminer, "mine_" + generation_strategy):
            raise_no_strategy_error(generation_strategy)

        generation_method = getattr(Dataminer, "mine_" + generation_strategy)
        for i in range(0, size, 8):
            bin_data += generation_method(i)
        return bin_data


if __name__ == "__main__":
    miner = Dataminer()
    data = miner.generate_data("iterative32", 8 * 10)
    print(data)
    print(len(data))
