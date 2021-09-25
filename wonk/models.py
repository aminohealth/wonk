"""Wonk data models."""

import copy
import json
import re
from typing import Any, Dict, List, Set, Tuple, Union

from .constants import ACTION_KEYS, JSON_ARGS, RESOURCE_KEYS, StatementKey

Statement = Dict[str, Any]
Policy = Dict[str, Any]


class InternalStatement:
    """An intermediate representation of an AWS policy statement."""

    def __init__(self, statement: Statement):
        """Convert an AWS statement into an internal representation that's easier to process."""

        statement = copy.deepcopy(statement)
        statement.pop(StatementKey.SID, None)

        self.action_key = which_type(statement, ACTION_KEYS)
        self.action_value = key_as_set(statement, self.action_key)
        statement.pop(self.action_key)

        self.resource_key = which_type(statement, RESOURCE_KEYS)
        self.resource_value = canonicalize_resources(key_as_set(statement, self.resource_key))
        statement.pop(self.resource_key)

        self.rest = statement

    def render(self) -> Statement:
        """Convert an internal statement into its AWS-ready representation."""

        statement = copy.deepcopy(self.rest)

        statement[self.action_key] = canonicalize_actions(self.action_value)
        statement[self.resource_key] = self.resource_value

        return statement

    def grouping_key(self) -> str:
        """Return a dict key that can be used to group this statement with others like it.

        Create a key that can be used to group similar statements. In other words, if there are two
        statements that have all of these keys in common, then they can be combined into a single
        statement.
        """

        elems: List[Union[str, Tuple[str, Any]]] = []

        # First, record whether this statement has Action or NotAction keys.
        elems.append(self.action_key)

        # Next, record whether it has a Resource or NotResource (and those canonical values).
        elems.append((self.resource_key, self.resource_value))

        # Finally, record the values of all the other keys in the statement
        for key, value in sorted(self.rest.items()):
            elems.append((key, value))

        return str(elems)

    def sorting_key(
        self,
    ) -> Tuple[bool, bool, bool, bool, int, str, int, List[str]]:
        """Return a key that sorts statements in the expected way.

        - Actions before NotActions
        - Resources before NotResources
        - Resource values of "*" before more specific values
        - Allow before Deny

        In the case of a tie, use the other policy-level fields and then the lists of actions to
        pick a winner.
        """

        # Create a tuple of increasingly specific conditions to sort on.
        #
        # Note: bools are ints, so False < True. If you want a statement with a given value to come
        # before those without it, write the expression like `key != "goodvalue"` so that the
        # resulting False will come first.

        return (
            # "Action" before "NotAction"
            self.action_key != "Action",
            # "Resource" before "NotResource"
            self.resource_key != "Resource",
            # Resource: * before other values
            self.resource_value != "*",
            # Allow before Deny
            self.rest != {StatementKey.EFFECT: "Allow"},
            # Short list of Principals and Conditions before longer list
            len(self.rest),
            # The values of Principals and Conditions
            json.dumps(self.rest, sort_keys=True, **JSON_ARGS[-1]),
            # Short list of actions before longer list. Note: Wonk should never make it this far
            # into the sorting key because any two statements this similar should have been
            # combined into a single statement before we get to here.
            len(self.action_value),
            # The values of the actions
            sorted(self.action_value),
        )


def canonicalize_actions(actions: Set[str]) -> Union[str, List[str]]:
    """Return the set of actions as either a single string or a sorted list of strings."""

    if len(actions) == 1:
        return next(iter(actions))

    keep_actions = set()

    # See if any of the actions look like "service:*". If so, we can discard any other actions like
    # "service:Foo" because they're already covered by the wildcard. This loop builds a list of
    # regular expressions that we can use to weed out redundant actions.
    #
    # Note that this could be much easier if you could guarantee that "*" would only be at the end
    # of the stream. Then you could sort the actions, and when you come across one ending with "*",
    # discard all of the following ones that start with the same string up until that "*". However,
    # even though we haven't stumbled across cases like "Foo*Bar" in the wild, nothing says they
    # can't exist.
    discard_patterns = []
    for action in actions:
        if "*" not in action:
            continue
        pattern = action.replace("*", ".*")
        discard_patterns.append(re.compile(fr"^{pattern}$"))
        # Keep the wildcard action!
        keep_actions.add(action)

    # Throw away any actions that are matched by any of the wildcard patterns defined in the
    # previous step.
    for action in actions:
        if not any(pattern.match(action) for pattern in discard_patterns):
            keep_actions.add(action)

    return sorted(keep_actions)


def canonicalize_resources(resources: Set[str]) -> Union[str, List[str]]:
    """Return the set of resources as either a single string or a sorted list of strings."""

    if len(resources) == 1:
        return next(iter(resources))

    return sorted(resources)


def key_as_set(statement: Statement, key: str) -> Set[str]:
    """Return the content's of the statements key as a (possibly empty) set of strings."""

    try:
        value = statement[key]
    except KeyError:
        return set()
    if isinstance(value, str):
        return {value}
    return set(value)


def which_type(statement: Statement, choices: Tuple[StatementKey, StatementKey]) -> str:
    """Return whichever of the choices of keys is in the statement.

    Note: All policy statements must have exactly one of these keys, so this raises an error if
    that isn't true.
    """

    left, right = choices
    has_left = left in statement
    has_right = right in statement

    if has_left and has_right:
        raise ValueError(f"Statement {statement} has both {left} and {right}")
    if not (has_left or has_right):
        raise ValueError(f"Statement {statement} has neither {left} nor {right}")

    return left.value if has_left else right.value
