import random

from gigue.helpers import align
from gigue.helpers import int_to_bytes32
from gigue.helpers import int_to_bytes64


def raise_no_strategy_error(generation_strategy):
    raise ValueError(f"No generation strategy named '{generation_strategy}'.")


class Dataminer:
    def __init__(self, address, size):
        self.address = align(address, 4)
        self.size = align(size, 8)

    def mine_random(self, i):
        return random.randbytes(8)

    def mine_iterative32(self, i):
        i = min(0xFFFF, i)
        return int_to_bytes32(i // 4) + int_to_bytes32(i // 4 + 1)

    def mine_iterative64(self, i):
        i = min(0xFFFFFFFF, i)
        return int_to_bytes64(i // 8)

    def generate_data(self, generation_strategy):
        bin_data = b""
        if not hasattr(Dataminer, "mine_" + generation_strategy):
            raise_no_strategy_error(generation_strategy)

        generation_method = getattr(Dataminer, "mine_" + generation_strategy)
        for i in range(0, self.size, 8):
            bin_data += generation_method(self, i)
        return bin_data


if __name__ == "__main__":
    miner = Dataminer(0x1000, 104)
    data = miner.generate_data("iterative32")
    print(data)
    print(len(data))
