"""Wonk exceptions."""


class WonkException(Exception):
    """Base class for exceptions in this package."""


class TooManyPoliciesError(WonkException):
    """Expected to find at most 10 policies in a policy set."""

    def __init__(self, policy_set, policies):
        super().__init__()
        self.policy_set = policy_set
        self.policies = policies


class UnpackableStatementsError(WonkException):
    """The statements can't be packed into an acceptable number of bins."""


class UnshrinkablePolicyError(WonkException):
    """The policy can't be encoded into a small enough JSON string."""


class ConfigException(WonkException):
    """Base class for configuration exceptions."""


class UnknownParentError(ConfigException):
    """The class inherits from a parent that's not defined."""
