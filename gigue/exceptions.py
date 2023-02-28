# =============================
#     Generator exceptions
# =============================


class GeneratorException(Exception):
    """
    Raise a generator exception. Easier to catch!
    """

    pass


class WrongAddressException(GeneratorException):
    """
    Raise when the interpretation/jit addresses are not ordered.
    """

    pass


class NotYetImplementedException(GeneratorException):
    """
    Raise when a functionality is not yet implemented.
    """

    pass


# =============================
#       Method exceptions
# =============================


class MethodException(Exception):
    """
    Raise a method exception. Easier to catch!
    """

    pass


class EmptySectionException(MethodException):
    """
    Raise if epilogue or prologue is not filled.
    """

    pass


class CallNumberException(MethodException):
    """
    Raised when the required call number does not fit in the method.
    """

    pass


class MutualCallException(MethodException):
    """
    Raised when two method call themselves (infinite loop).
    """

    pass


class RecursiveCallException(MethodException):
    """
    Raised when a method calls itself.
    """

    pass