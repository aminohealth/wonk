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
        self.action_value = value_to_set(statement, self.action_key)
        statement.pop(self.action_key)

        self.resource_key = which_type(statement, RESOURCE_KEYS)
        self.resource_value = canonicalize_resources(value_to_set(statement, self.resource_key))
        statement.pop(self.resource_key)

        self.rest = statement

    def render(self) -> Statement:
        """Convert an internal statement into its AWS-ready representation."""

        statement = copy.deepcopy(self.rest)

        statement[self.action_key] = canonicalize_actions(self.action_value)
        statement[self.resource_key] = self.resource_value

        return statement

    def grouping_for_actions(self) -> str:
        """Make a key that can be used to group this statement's actions with others like it.

        Create a key that can be used to group statements which are similar except for their
        actions. In other words, if there are two statements that have all of these keys in common,
        then their actions can be combined into a single statement.

        """

        elems: List[Union[str, Tuple[str, Any]]] = []

        # First, record whether this statement has Action or NotAction keys.
        elems.append(self.action_key)

        # Next, record whether it has a Resource or NotResource (and those values).
        elems.append((self.resource_key, self.resource_value))

        # Finally, record the values of all the other keys in the statement
        for key, value in sorted(self.rest.items()):
            elems.append((key, value))

        return str(elems)

    def grouping_for_resources(self) -> str:
        """Make a key that can be used to group this statement's resources with others like it.

        Create a key that can be used to group statements which are similar except for their
        resources. In other words, if there are two statements that have all of these keys in
        common, then their resources can be combined into a single statement.
        """

        elems: List[Union[str, Tuple[str, Any]]] = []

        # First, record whether this statement has Action or NotAction keys (and those values).
        elems.append((self.action_key, sorted(self.action_value)))

        # Next, record whether it has a Resource or NotResource.
        elems.append(self.resource_key)

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


def deduped_items(items: Set[str]) -> List[str]:
    """Return a sorted list of all the unique items in `items`, ignoring case."""

    # First, group all items by their casefolded values. This lumps "foo" and "FOO" together.
    unique: Dict[str, List[str]] = {}
    for item in items:
        unique.setdefault(item.casefold(), []).append(item)

    # Sort the dictionary by it's casefolded keys, then return the first item in each key's sorted
    # list of values. For instance, if `unique["foo"] == ["fOO", "FOO"]`, then return "FOO" (which
    # comes first when ["foo", "FOO"] is sorted).
    return [sorted(values)[0] for _, values in sorted(unique.items())]


def collect_wildcard_matches(items: Set[str]) -> Union[str, List[str]]:
    """Return the reduced set of items as either a single string or a sorted list of strings.

    This removes wildcard matches from the set. If the set contains both "foo*" and "foobar",
    "foobar" will be removed because "foo*" already covers it.
    """

    if len(items) == 1:
        return items.pop()

    # Build a dict of wildcard items to their regular expressions.
    patterns: Dict[str, re.Pattern] = {}
    for item in items:
        if "*" not in item:
            continue

        pattern_string = item.replace("*", ".*")
        patterns[item.casefold()] = re.compile(fr"^{pattern_string}$", re.IGNORECASE)

    new_items = []
    for item in deduped_items(items):
        # If this item matches any of the patterns (other than itself!), then skip it. If it
        # doesn't, add it to the list of items to keep.
        if not any(
            pattern_item != item.casefold() and pattern.match(item)
            for pattern_item, pattern in patterns.items()
        ):
            new_items.append(item)

    return new_items


def canonicalize_actions(actions: Set[str]) -> Union[str, List[str]]:
    """Return the set of actions as a sorted list of strings."""

    return collect_wildcard_matches(actions)


def canonicalize_resources(resources: Set[str]) -> Union[str, List[str]]:
    """Return the set of resources as either a single string or a sorted list of strings."""

    if "*" in resources:
        return "*"

    return collect_wildcard_matches(resources)


def to_set(value: Union[str, List[str]]) -> Set[str]:
    """Convert a string or list of strings to a set with that key or keys."""

    if isinstance(value, str):
        return {value}
    return set(value)


def value_to_set(statement: Statement, key: str) -> Set[str]:
    """Return the content's of the statements key as a (possibly empty) set of strings."""

    try:
        value = statement[key]
    except KeyError:
        return set()
    return to_set(value)


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
