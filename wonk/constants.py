"""Common Wonk constants."""

from enum import Enum
from typing import Any, Dict, Tuple


class PolicyKey(str, Enum):
    """Keys found in a policy."""

    ID = "Id"
    STATEMENT = "Statement"
    VERSION = "Version"


class StatementKey(str, Enum):
    """Keys found in a statement."""

    EFFECT = "Effect"
    ACTION = "Action"
    NOTACTION = "NotAction"
    PRINCIPAL = "Principal"
    NOTPRINCIPAL = "NotPrincipal"
    RESOURCE = "Resource"
    NOTRESOURCE = "NotResource"
    CONDITION = "Condition"
    SID = "Sid"


# This are the arguments to `json.dumps` we'll use to try to pack as as much information into a
# policy as we can. These are ordered from most desirable (and with the largest output) to least
# (and most compact).
JSON_ARGS: Tuple[Dict[str, Any], ...] = (
    {"indent": 4},
    {"indent": 2},
    {"indent": "\t"},
    {},
    {"separators": (",", ":")},
)

ACTION_KEYS = (StatementKey.ACTION, StatementKey.NOTACTION)
RESOURCE_KEYS = (StatementKey.RESOURCE, StatementKey.NOTRESOURCE)

MAX_MANAGED_POLICY_SIZE = 6_144
