class RunnerException(Exception):
    """
    Raise a runner exception, parent class.
    """

    pass


class EnvironmentException(RunnerException):
    """
    Raised when env vars are not found
    """

    pass


class IncorrectSeedsNumberException(RunnerException):
    """
    Raised when the number of seeds does not correspond to
    the number of runs
    """

    pass


class UnknownIsolationSolutionException(RunnerException):
    """
    Raised when the isolation solution proposed is unknown
    """

    pass
