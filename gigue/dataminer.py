import random
from typing import Callable

from gigue.helpers import align, int_to_bytes32, int_to_bytes64


def raise_no_strategy_error(generation_strategy):
    raise ValueError(f"No generation strategy named '{generation_strategy}'.")


class Dataminer:
    @staticmethod
    def mine_zeroes(*args, **kwargs) -> bytes:
        return int_to_bytes64(0)

    @staticmethod
    def mine_random(*args, **kwargs) -> bytes:
        return random.randbytes(8)

    @staticmethod
    def mine_iterative32(i: int, *args, **kwargs) -> bytes:
        i = min(0xFFFF, i)
        return int_to_bytes32(i // 4) + int_to_bytes32(i // 4 + 1)

    @staticmethod
    def mine_iterative64(i: int) -> bytes:
        i = min(0xFFFFFFFF, i)
        return int_to_bytes64(i // 8)

    @staticmethod
    def generate_data(generation_strategy: str, size: int) -> bytes:
        size = align(size, 8)
        bin_data: bytes = b""
        try:
            generation_method: Callable = getattr(
                Dataminer, "mine_" + generation_strategy
            )
        except AttributeError as err:
            raise AttributeError(
                f"Dataminer has no generation strategy named '{generation_strategy}'."
            ) from err

        for i in range(0, size, 8):
            bin_data += generation_method(i)
        return bin_data


if __name__ == "__main__":
    miner = Dataminer()
    data = miner.generate_data("iterative32", 8 * 10)
