"""Wonk data models."""

import copy
import json
import math
import re
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Dict, Generator, List, Set, Tuple, Union

from .constants import (
    ACTION_KEYS,
    JSON_ARGS,
    MAX_MANAGED_POLICY_SIZE,
    RESOURCE_KEYS,
    PolicyKey,
    StatementKey,
)
from .exceptions import UnshrinkablePolicyError

StatementData = Dict[str, Any]


@dataclass(frozen=True)
class Statement:
    """An intermediate representation of an AWS policy statement."""

    statement: StatementData

    def __str__(self) -> str:
        """Return the smallest representation of the Statement."""

        return smallest_json(self.as_json())

    @property
    def action_key(self):
        """Return whichever of the statement's Action or NotAction key is defined."""

        return which_type(self.statement, ACTION_KEYS)

    @property
    def action_value(self):
        """Return the value of the statement's Action or NotAction key."""

        return value_to_set(self.statement, self.action_key)

    @property
    def resource_key(self):
        """Return whichever of the statement's Resource or NotResource key is defined."""

        return which_type(self.statement, RESOURCE_KEYS)

    @property
    def resource_value(self):
        """Return the value of the statement's Resource or NotResource key."""

        return canonicalize_resources(value_to_set(self.statement, self.resource_key))

    @property
    def rest(self):
        """Return everything but the statement's {Not,}Action, {Not,}Resource, and Sid keys."""

        rest = copy.deepcopy(self.statement)
        rest.pop(StatementKey.SID, None)
        del rest[self.action_key]
        del rest[self.resource_key]
        return rest

    def replace(self, *, action_value=None, resource_value=None):
        """Return a copy of the statement with the given keys replaced."""

        statement = copy.deepcopy(self.statement)
        if action_value is not None:
            statement[self.action_key] = action_value
        if resource_value is not None:
            statement[self.resource_key] = resource_value

        return self.__class__(statement)

    def as_json(self) -> StatementData:
        """Convert an internal statement into its AWS-ready representation."""

        statement = copy.deepcopy(self.rest)

        statement[self.action_key] = collect_wildcard_matches(self.action_value)
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

    def split(self, max_statement_size: int) -> Generator[StatementData, None, None]:
        """Split the original statement into a series of chunks that are below the size limit."""

        statement_action = self.action_key
        actions = collect_wildcard_matches(self.action_value)

        # Why .45? If we need to break a statement up, we may as well make the resulting parts
        # small enough that the solver can easily pack them with others. A bad outcome here would
        # be to end up with 20 statements that were each 60% of the maximum size so that no two
        # could be packed together. However, there _is_ a little bit of overhead in splitting them
        # because each statement is wrapped in a dict that may have several keys in it. In the end,
        # "a little smaller than half the maximum" seemed about right.

        chunks = math.ceil(len(str(self)) / (max_statement_size * 0.45))
        chunk_size = math.ceil(len(actions) / chunks)

        for base in range(0, len(actions), chunk_size):
            sub_statement = copy.deepcopy(self.rest)
            sub_statement[self.resource_key] = self.resource_value
            sub_statement[statement_action] = actions[base : base + chunk_size]  # noqa: E203
            yield sub_statement


@dataclass(frozen=True)
class Policy:
    """Represent an AWS policy."""

    DEFAULT_ID = "*" * 32

    statements: List[Statement]
    version: str = field(default="2012-10-17")

    def __post_init__(self):
        """Clean up passed-in values."""

        # Sort everything that can be sorted. This ensures that separate runs of the program
        # generate the same outputs, which makes `git diff` happy.
        self.statements.sort(key=Statement.sorting_key)

    def __str__(self) -> str:
        """Return the smallest possible JSON representation of the Policy."""

        return smallest_json(
            {
                PolicyKey.VERSION: self.version,
                PolicyKey.ID: self.DEFAULT_ID,  # Don't compute the Policy's ID just for this.
                PolicyKey.STATEMENT: [statement.as_json() for statement in self.statements],
            }
        )

    def __eq__(self, other) -> bool:
        """Return True if this Policy is identical to the other one."""

        return self.as_json() == other.as_json()

    def as_json(self) -> Dict[str, Any]:
        """Represent the Policy as a JSON object."""

        return {
            PolicyKey.VERSION: self.version,
            PolicyKey.ID: self.id,
            PolicyKey.STATEMENT: [statement.as_json() for statement in self.statements],
        }

    def render(self) -> str:
        """Return the most aesthetic representation of the Policy that fits in the size."""

        data = self.as_json()
        for args in JSON_ARGS:
            packed = json.dumps(data, **args)
            if len(packed) <= MAX_MANAGED_POLICY_SIZE:
                return packed

        raise UnshrinkablePolicyError(
            f"Unable to shrink the data into into {MAX_MANAGED_POLICY_SIZE} characters: {data!r}"
        )

    @property
    def id(self) -> str:
        """Return the Policy's ID as a hash of its contents."""

        digest = sha256(str(self).encode()).hexdigest()
        return digest[: len(self.DEFAULT_ID)]

    @classmethod
    def from_dict(cls, data):
        """Create a Policy object from a dictionary."""

        statements = data.get(PolicyKey.STATEMENT, [])

        # According to the policy language grammar (see
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html) the
        # Statement key should have a list of statements, and indeed that's almost always the case.
        # Some of Amazon's own policies (see AWSCertificateManagerReadOnly) have a Statement key
        # that points to a dict instead of a list of dicts.
        #
        # This ensures that we're always dealing with a list of statements.
        if isinstance(statements, dict):
            statements = [statements]

        kwargs = {"statements": [Statement(statement) for statement in statements]}

        try:
            version = data[PolicyKey.VERSION]
        except KeyError:
            pass
        else:
            kwargs["version"] = version

        return cls(**kwargs)  # type: ignore


def smallest_json(data: dict) -> str:
    """Return the smallest possible JSON representation of the dict."""

    return json.dumps(data, sort_keys=True, **JSON_ARGS[-1])


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
        patterns[item.casefold()] = re.compile(rf"^{pattern_string}$", re.IGNORECASE)

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


def value_to_set(statement: StatementData, key: str) -> Set[str]:
    """Return the contents of the statements key as a (possibly empty) set of strings."""

    try:
        value = statement[key]
    except KeyError:
        return set()
    return to_set(value)


def which_type(statement: StatementData, choices: Tuple[StatementKey, StatementKey]) -> str:
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
