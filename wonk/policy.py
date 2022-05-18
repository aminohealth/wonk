"""Manage AWS policies."""

import json
import pathlib
import re
from typing import Dict, List, Tuple

from xdg import xdg_cache_home

from wonk import aws, exceptions, optimizer
from wonk.constants import MAX_MANAGED_POLICY_SIZE
from wonk.models import Policy, Statement, canonicalize_resources, smallest_json, to_set

POLICY_CACHE_DIR = xdg_cache_home() / "com.amino.wonk" / "policies"


def minify(policies: List[Policy]) -> List[Statement]:
    """Reduce the input policies to the minimal set of functionally identical equivalents."""

    internal_statements: List[Statement] = []
    for policy in policies:
        internal_statements.extend(policy.statements)

    this_changed = True
    while this_changed:
        changed, internal_statements = grouped_actions(internal_statements)
        if not changed:
            this_changed = False
        changed, internal_statements = grouped_resources(internal_statements)
        if not changed:
            this_changed = False

    return internal_statements


def grouped_actions(statements: List[Statement]) -> Tuple[bool, List[Statement]]:
    """Merge similar policies' actions.

    Returns a list of statements whose actions have been combined when possible.
    """

    statement_sets: Dict[str, Statement] = {}
    changed = False

    for statement in statements:
        group = statement.grouping_for_actions()

        try:
            existing_item = statement_sets[group]
        except KeyError:
            statement_sets[group] = statement
            continue

        new_action_value = existing_item.action_value | statement.action_value
        if existing_item.action_value != new_action_value:
            changed = True
            statement_sets[group] = existing_item.replace(action_value=new_action_value)

    return changed, list(statement_sets.values())


def grouped_resources(statements: List[Statement]) -> Tuple[bool, List[Statement]]:
    """Merge similar policies' resources.

    Returns a list of statements whose resources have been combined when possible.
    """

    statement_sets: Dict[str, Statement] = {}
    changed = False

    for statement in statements:
        group = statement.grouping_for_resources()

        try:
            existing_item = statement_sets[group]
        except KeyError:
            statement_sets[group] = statement
            continue

        new_resource_value = canonicalize_resources(
            to_set(existing_item.resource_value) | to_set(statement.resource_value)
        )
        if existing_item.resource_value != new_resource_value:
            changed = True
            statement_sets[group] = existing_item.replace(resource_value=new_resource_value)

    return changed, list(statement_sets.values())


def combine(policies: List[Policy]) -> List[Policy]:
    """Combine policy files into the smallest possible set of outputs."""

    new_policy = Policy(statements=minify(policies))

    # Simplest case: we're able to squeeze everything into a single file. This is the ideal.
    try:
        new_policy.render()
    except exceptions.UnshrinkablePolicyError:
        pass
    else:
        return [new_policy]

    # Well, that didn't work. Now we need to split the policy into several documents. Subtract the
    # length of the tightest packaging of the policy "envelope" from the maximum size, then
    # subtract the number of statements[1] (because we might have to glue the results together
    # with commas). This is how much room we have to pack statements into.
    #
    # [1] Why "len(statements) - 2"? Because you can glue n statements together with n-1 commas,
    # and it's guaranteed that we can fit at most n-1 statements into a single document because if
    # we could fit all n then we wouldn't have made it to this point in the program. And yes, this
    # is exactly the part of the program where we start caring about every byte.
    minimum_possible_policy_size = len(str(Policy(statements=[])))
    max_number_of_commas = len(new_policy.statements) - 2
    max_statement_size = (
        MAX_MANAGED_POLICY_SIZE - minimum_possible_policy_size - max_number_of_commas
    )

    packed_list = []
    for statement in new_policy.statements:
        packed = str(statement)
        if len(packed) <= max_statement_size:
            packed_list.append(packed)
            continue

        for statement_dict in statement.split(max_statement_size):
            packed_list.append(smallest_json(statement_dict))

    statement_sets = optimizer.pack_statements(packed_list, max_statement_size, 10)

    policies = []
    for statement_set in statement_sets:
        # The splitting process above might have resulted in this policy having multiple statements
        # that could be merged back together. The easiest way to handle this is to create a new
        # policy as-is, then group its statements together into *another* new, optimized policy,
        # and emit that one.
        unmerged_policy = Policy(
            statements=[Statement(json.loads(statement)) for statement in statement_set]
        )
        merged_policy = Policy(statements=minify([unmerged_policy]))
        policies.append(merged_policy)

    return policies


def policy_set_pattern(policy_set: str) -> re.Pattern:
    """Return a regexp matching the policy set's name."""

    final = policy_set.rsplit("/", maxsplit=1)[-1]
    return re.compile(rf"^{final}_\d+$")


def write_policy_set(output_dir: pathlib.Path, base_name: str, policies: List[Policy]):
    """Write the packed sets, return the names of the files written, and collect garbage."""

    # Get the list of existing files for this policy set so that we can delete them later. First,
    # get a list of candidates with Path.glob() because that's faster and easier than getting a
    # list of _every_ file and filtering it with Python. Then use a regular expression to match
    # each candidate so that policy set "foo" doesn't unintentionally delete policy set "foo_bar"'s
    # files.

    pattern = policy_set_pattern(base_name)
    cleanup = {
        candidate
        for candidate in output_dir.glob(f"{base_name}_*")
        if pattern.match(candidate.stem)
    }
    if len(cleanup) > 10:
        # Wonk only creates at most 10 policies for a policy set. If we've found more than 10
        # matches then something's gone awry, like the policy set is "*" or such. Either way, pull
        # the plug and refuse to delete them.
        raise exceptions.TooManyPoliciesError(base_name, len(cleanup))

    # For consistency, delete all of the pre-existing files before we start so we can't be left
    # with a mix of old and new files.
    for old in cleanup:
        old.unlink()

    # Write each of the files that file go into this policy set, and create a list of the filenames
    # we've written.
    output_filenames = []
    for i, policy in enumerate(policies, 1):
        output_path = output_dir / f"{base_name}_{i}.json"
        output_filenames.append(str(output_path))

        output_path.write_text(policy.render())

    return output_filenames


def make_cache_file(name: str, version: str) -> pathlib.Path:
    """Return the path to the document's cache file."""

    cache_dir = POLICY_CACHE_DIR / name
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{version}.json"


def fetch(client, arn: str, force: bool = False) -> str:
    """Return the contents of the policy."""

    current_version = aws.get_policy_version(client, arn)
    cache_file = make_cache_file(aws.name_for(arn), current_version)

    policy_doc = None
    try:
        if not force:
            policy_doc = cache_file.read_text()
    except FileNotFoundError:
        pass

    if policy_doc is None:
        policy_doc = aws.get_policy(client, arn, current_version)
        cache_file.write_text(policy_doc)

    return policy_doc
