from math import ceil
import random
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


def reverse_endianness(value: bytes) -> bytes:
    return int_to_bytes64(int.from_bytes(value, "big"))


# Distributions
# \____________


# TODO: Discrete distribution (bernoulli?)
# TODO: Extract expected mu/sigma
# TODO: Users should rather use mean/std to define the range


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
    int_value: int = ceil(random.gauss(mu=mu, sigma=sigma))
    box_value: int = max(min(int_value, up_bound), low_bound)
    # import math
    # print(f"sigma {sigma}, mu {mu}, folded {sigma * math.sqrt(2/math.pi)}")
    return box_value


def generate_trunc_norm(
    variance: float, std_dev: float, lower_bound: float, higher_bound: float
):
    # Truncation of the normal distribution should use a new sample and
    # not box the value directly!
    x = random.gauss(variance, std_dev)
    while not lower_bound <= x <= higher_bound:
        x = random.gauss(variance, std_dev)
    return x


def generate_poisson(lmbda):
    # Poisson generator based upon the inversion by sequential search
    # based on Devroye "Discrete univariate distributions"
    # init:
    #     Let x ← 0, p ← e−λ, s ← p.
    #     Generate uniform random number u in [0,1].
    # while u > s do:
    #     x ← x + 1.
    #     p ← p × λ / x.
    #     s ← s + p.
    # return x.
    x = 0
    p = math.exp(-lmbda)
    s = p
    u = random.random()
    while u > s:
        x = x + 1
        p *= lmbda / x
        s = s + p
    return x


if __name__ == "__main__":
    import matplotlib.pyplot as plt
    import math

    # Poisson distribution
    lambda_value = 2  # Lambda parameter of the Poisson distribution
    data = [generate_poisson(lambda_value) for _ in range(100000)]
    plt.hist(data, bins=100)
    plt.show()

    # Truncated normal distribution
    variance = 0.25
    std_dev = 0.2
    lower_bound = 0
    higher_bound = 1.0
    data = [
        generate_trunc_norm(variance, std_dev, lower_bound, higher_bound)
        for _ in range(100000)
    ]
    # sample_mean = sum(data) / len(data)
    # print(sample_mean)
    plt.hist(data, bins=100)
    plt.show()
