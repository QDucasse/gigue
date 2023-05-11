from math import ceil
from random import gauss
from typing import Any, Generator, List, Union

# List Helpers
# \________________


def flatten_list(nested_list: List[Any]) -> List[Any]:
    return [item for sublist in nested_list for item in sublist]


def window(arr: List[Any], k: int) -> Generator:
    for i in range(len(arr) - k + 1):
        yield arr[i : i + k]


def mean(list: Union[List[int], List[float]]):
    return sum(list) / len(list)

# Sign extension
# \_____________


def to_signed(value: int, size: int) -> int:
    sign_mask: int = 1 << (size - 1)  # 0b100000...
    mask: int = (1 << size) - 1  # 0b01111111...
    return ((value & mask) ^ sign_mask) - sign_mask


def to_unsigned(value: int, size: int) -> int:
    if value >= 0:
        return value
    mask: int = (1 << size) - 1  # 0b01111111...
    return mask - abs(value) + 1


# Format
# \_____


def format_to(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 1)


def format_to_aligned(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 2)


def align(value: int, alignment: int) -> int:
    return (value // alignment) * alignment


# Byte/int conversion
# \__________________


def int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def int_to_bytes64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "little")


# Distributions
# \____________


def gaussian_between(low_bound: int, up_bound: int) -> int:
    """
    We select
        mu + 3 * sigma = low
        mu - 3 * sigma = up
    This way there should be 0.1% values above and 0.1% below!
    """
    # if low_bound <= up_bound:
    #     raise Exception
    sigma: float = (up_bound - low_bound) / 6
    mu: float = low_bound + 3 * sigma
    int_value: int = ceil(gauss(mu=mu, sigma=sigma))
    box_value: int = max(min(int_value, up_bound), low_bound)
    return box_value
