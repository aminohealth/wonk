"""Manage Wonk's configuration."""

import pathlib
from typing import Any, Dict, List

import yaml
from pydantic import BaseModel
from toposort import toposort_flatten  # type: ignore

from wonk.exceptions import UnknownParentError


class PolicySet(BaseModel):
    """Describes a policy set."""

    name: str
    managed: List[str] = []
    local: List[str] = []
    inherits: List[str] = []

    def __ior__(self, other):
        """Append the values from another policy set onto this one's."""

        # This is not an efficient algorithm, but it maintains ordering which lends stability to
        # the final output files. These lists are almost always going to be very short anyway, and
        # an easy to read algorithm is better than a more efficient but complex one for these
        # purposes.
        for value in other.managed:
            if value not in self.managed:
                self.managed.append(value)

        for value in other.local:
            if value not in self.local:
                self.local.append(value)

        return self


class Config(BaseModel):
    """Describes a Wonk configuration file."""

    policy_sets: Dict[str, PolicySet]


def load_config(config_path: pathlib.Path = None) -> Config:
    """Load a configuration file and return its parsed contents."""

    if config_path is None:
        config_path = pathlib.Path("wonk.yaml")

    data = yaml.load(config_path.read_text(), Loader=yaml.SafeLoader)
    return parse_config(data)


def parse_config(block_all_config: Dict[str, Any]) -> Config:
    """Parse the dictionary containing all Wonk configuration into a Config object."""

    try:
        block_policy_sets = block_all_config["policy_sets"] or {}
    except KeyError:
        policy_sets = {}
    else:
        policy_sets = parse_policy_sets(block_policy_sets)

    return Config(policy_sets=policy_sets)  # type: ignore


def parse_policy_sets(block_policy_sets: Dict[str, Any]) -> Dict[str, PolicySet]:
    """Parse the dictionary containing policy set definitions into a dict of PolicySets."""

    policy_sets = {}

    deps = {}
    for name, definition in block_policy_sets.items():
        with_name = {**definition, **{"name": name}}

        policy_set = PolicySet(**with_name)
        policy_sets[name] = policy_set

        for parent_name in policy_set.inherits:
            if parent_name not in block_policy_sets:
                raise UnknownParentError(name, parent_name)

        # Build a dependency graph from the set of inheritance definitions from the classes.
        deps[name] = set(policy_set.inherits)

    for name in toposort_flatten(deps):
        policy_set = policy_sets[name]
        for parent_name in policy_set.inherits:
            policy_set |= policy_sets[parent_name]

    return policy_sets
