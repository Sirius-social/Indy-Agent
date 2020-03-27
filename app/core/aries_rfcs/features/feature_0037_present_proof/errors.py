class BaseMachineException(Exception):

    def __init__(self, message: str=None):
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.__class__.__name__, self.message)


class ImpossibleStatus(BaseMachineException):
    pass


class ImpossibleForStatus(BaseMachineException):
    pass


class ErrorStatus(BaseMachineException):
    pass
