from math import ceil
from random import gauss

# List manipulation
# \________________


def flatten_list(nested_list):
    return [item for sublist in nested_list for item in sublist]


# Sign extension
# \_____________


def to_signed(value, size):
    sign_mask = 1 << (size - 1)  # 0b100000...
    mask = (1 << size) - 1  # 0b01111111...
    return ((value & mask) ^ sign_mask) - sign_mask


def to_unsigned(value, size):
    if value >= 0:
        return value
    mask = (1 << size) - 1  # 0b01111111...
    return mask - abs(value) + 1


# Format
# \_____


def format_to(value, size):
    return abs(value) & ((1 << size) - 1)


def format_to_aligned(value, size):
    return abs(value) & ((1 << size) - 2)


def align(value, alignment):
    return (value // alignment) * alignment


# Byte/int conversion
# \__________________


def int_to_bytes32(value):
    return value.to_bytes(4, "little")


def int_to_bytes64(value):
    return value.to_bytes(8, "little")


def bytes_to_int(value):
    return int.from_bytes(value, "little")


# Distributions
# \____________


def gaussian_between(low_bound, up_bound):
    """
    We select
        mu + 3 * sigma = low
        mu - 3 * sigma = up
    This way there should be 0.1% values above and 0.1% below!
    """
    # if low_bound <= up_bound:
    #     raise Exception
    sigma = (up_bound - low_bound) / 6
    mu = low_bound + 3 * sigma
    int_value = ceil(gauss(mu=mu, sigma=sigma))
    box_value = max(min(int_value, up_bound), low_bound)
    return box_value


# List Windows
# \___________


def window(arr, k):
    for i in range(len(arr) - k + 1):
        yield arr[i : i + k]
