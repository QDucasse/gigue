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


# =============================
#    Disassembler exceptions
# =============================


class DisassemblerException(Exception):
    """
    Raise a disassembler exception. Easier to catch!
    """

    pass


class UnknownInstructionException(DisassemblerException):
    """
    Raised when no match is detected while disassembling an instruction.
    """

    pass


# =============================
#      Builder exceptions
# =============================


class BuilderException(Exception):
    """
    Raise a builder exception. Easier to catch!
    """

    pass


class WrongOffsetException(BuilderException):
    """
    Offset is incorrect.
    """

    pass


class InstructionAlignmentNotDefined(BuilderException):
    """
    Alignment for instruction is not defined.
    """

    pass
