# List manipulation
def flatten_list(nested_list):
    return [item for sublist in nested_list for item in sublist]


# Sign extension
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
def format_to(value, size):
    return abs(value) & ((1 << size) - 1)


def format_to_aligned(value, size):
    return abs(value) & ((1 << size) - 2)


# Byte/int conversion
def int_to_bytes(value):
    return value.to_bytes(4, "little")


def bytes_to_int(value):
    return int.from_bytes(value, "little")


# Object Dictionary
class ObjDict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            raise AttributeError("No such attribute: " + name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        if name in self:
            del self[name]
        else:
            raise AttributeError("No such attribute: " + name)
