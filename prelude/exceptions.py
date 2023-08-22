class PreludeException(Exception):
    """
    Raise a prelude exception, parent class.
    """

    pass


class MissingExampleException(PreludeException):
    """
    Raised when no example was found for the corresponding key
    """

    pass


class MissingHelperException(PreludeException):
    """
    Raised when no helper was found for the corresponding argument
    """

    pass
