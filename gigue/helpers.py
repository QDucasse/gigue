import math
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
    if not list:
        return 0
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
    #     Let x ← 0, p ← e^(−λ), s ← p.
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


def generate_zero_truncated_poisson(lmbda):
    # Poisson generator based upon the inversion by sequential search
    # based on Devroye "Discrete univariate distributions"
    # init:
    #      Let x ← 1, p ← e^(−λ) / (1 - e^(−λ)) * λ, s ← p.
    #      Generate uniform random number u in [0,1].
    # while u > s do:
    #      x ← x + 1.
    #      p ← p * λ / x.
    #      s ← s + p.
    # return x.
    if lmbda == 0:
        raise ZeroDivisionError
    x = 1
    p = math.exp(-lmbda) / (1 - math.exp(-lmbda)) * lmbda
    s = p
    u = random.random()
    while s < u:
        x = x + 1
        p *= lmbda / x
        s = s + p
    return x


def mean_zero_truncated_poisson(lmbda):
    # Note: As 0 is not available, the mean is not equal to λ anymore
    # but rather to λ / (1 - e^(−λ))
    # Example values for λ are:
    # λ  |   mean
    # 1  | 1.58197670686932
    # 2  | 2.31303528549933
    # 3  | 3.15718708947376
    # 4  | 4.07462944145509
    # 5  | 5.03391827453152
    # 6  | 6.01490946994106
    # 7  | 7.00638899977255
    # 8  | 8.00268460160673
    # 9  | 9.00111082532351
    # 10 | 10.00045401991009
    return lmbda / (1 - math.exp(-lmbda))


def poisson_chernoff_bound(lmbda, alpha):
    # lambda is the poisson parameter and alpha the confidence level
    # ensuring that any generated value following poisson(lambda) is
    # bounded by k with a confidence level of (1 - alpha)
    k = 1
    while True:
        bound = min(
            math.exp(-lmbda) * math.pow(lmbda, k) / math.factorial(k),
            math.exp(-lmbda) * math.pow((math.exp(1) * lmbda / k), k),
        )
        if bound <= alpha:
            return k
        k += 1


def generate_pharo_pic_nb():
    # Define the probabilities based on (Miranda et al. 2018)
    probabilities = [0.9, 0.08, 0.02]

    random_number = random.random()
    # Monomorphic
    if random_number < probabilities[0]:
        return 1
    # Polymorphic
    elif random_number < probabilities[0] + probabilities[1]:
        return random.randint(2, 6)
    # Megamorphic
    else:
        return random.randint(6, 10)


if __name__ == "__main__":
    import matplotlib.pyplot as plt

    # Poisson distribution
    lambda_value = 3  # Lambda parameter of the Poisson distribution
    data = [generate_zero_truncated_poisson(lambda_value) for _ in range(100000)]
    print(max(data))
    print(poisson_chernoff_bound(lambda_value, 0.00001))
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

    # ZTP means
    for lmbda in range(1, 25):
        print(
            f"For lambda={lmbda}, the corrresponding ZTP mean is"
            f" {mean_zero_truncated_poisson(lmbda)}"
        )
