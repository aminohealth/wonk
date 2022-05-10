"""Manage AWS policies."""

import json
import math
import pathlib
import re
from typing import Dict, Generator, List, Tuple

from xdg import xdg_cache_home

from wonk import aws, exceptions, optimizer
from wonk.constants import ACTION_KEYS, JSON_ARGS, MAX_MANAGED_POLICY_SIZE
from wonk.models import (
    InternalStatement,
    Policy,
    Statement,
    canonicalize_resources,
    to_set,
    which_type,
)

POLICY_CACHE_DIR = xdg_cache_home() / "com.amino.wonk" / "policies"


def minify(policies: List[Policy]) -> List[InternalStatement]:
    """Reduce the input policies to the minimal set of functionally identical equivalents."""

    internal_statements: List[InternalStatement] = []
    for policy in policies:
        # According to the policy language grammar (see
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html) the
        # Statement key should have a list of statements, and indeed that's almost always the case.
        # Some of Amazon's own policies (see AWSCertificateManagerReadOnly) have a Statement key
        # that points to a dict instead of a list of dicts. This ensures that we're always dealing
        # with a list of statements.
        statements = policy.statement
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            internal_statements.append(InternalStatement(statement))

    this_changed = True
    while this_changed:
        changed, internal_statements = grouped_actions(internal_statements)
        if not changed:
            this_changed = False
        changed, internal_statements = grouped_resources(internal_statements)
        if not changed:
            this_changed = False

    return internal_statements


def grouped_actions(statements: List[InternalStatement]) -> Tuple[bool, List[InternalStatement]]:
    """Merge similar policies' actions.

    Returns a list of statements whose actions have been combined when possible.
    """

    statement_sets: Dict[str, InternalStatement] = {}
    changed = False

    for statement in statements:
        group = statement.grouping_for_actions()

        try:
            existing_item = statement_sets[group]
        except KeyError:
            statement_sets[group] = statement
        else:
            new_action_value = existing_item.action_value | statement.action_value
            if existing_item.action_value != new_action_value:
                changed = True
                existing_item.action_value = new_action_value

    return changed, list(statement_sets.values())


def grouped_resources(statements: List[InternalStatement]) -> Tuple[bool, List[InternalStatement]]:
    """Merge similar policies' resources.

    Returns a list of statements whose resources have been combined when possible.
    """

    statement_sets: Dict[str, InternalStatement] = {}
    changed = False

    for statement in statements:
        group = statement.grouping_for_resources()

        try:
            existing_item = statement_sets[group]
        except KeyError:
            statement_sets[group] = statement
        else:
            new_resource_value = canonicalize_resources(
                to_set(existing_item.resource_value) | to_set(statement.resource_value)
            )
            if existing_item.resource_value != new_resource_value:
                changed = True
                existing_item.resource_value = new_resource_value

    return changed, list(statement_sets.values())


def render(statements: List[InternalStatement]) -> Policy:
    """Turn the contents of the statement sets into a valid AWS policy."""

    # Sort everything that can be sorted. This ensures that separate runs of the program generate
    # the same outputs, which 1) makes `git diff` happy, and 2) lets us later check to see if we're
    # actually updating a policy that we've written out, and if so, skip writing it again (with a
    # new `Id` key).
    return Policy(
        statement=[
            statement.render()
            for statement in sorted(statements, key=lambda obj: obj.sorting_key())
        ]
    )


def tiniest_json(data: Statement) -> str:
    """Return the smallest representation of the data."""
    return json.dumps(data, sort_keys=True, **JSON_ARGS[-1])


def split_statement(
    statement: Statement, max_statement_size: int
) -> Generator[Statement, None, None]:
    """Split the original statement into a series of chunks that are below the size limit."""

    statement_action = which_type(statement, ACTION_KEYS)
    actions = statement[statement_action]

    # Why .45? If we need to break a statement up, we may as well make the resulting parts small
    # enough that the solver can easily pack them with others. A bad outcome here would be to end
    # up with 20 statements that were each 60% of the maximum size so that no two could be packed
    # together. However, there _is_ a little bit of overhead in splitting them because each
    # statement is wrapped in a dict that may have several keys in it. In the end, "a little
    # smaller than half the maximum" seemed about right.

    chunks = math.ceil(len(tiniest_json(statement)) / (max_statement_size * 0.45))
    chunk_size = math.ceil(len(actions) / chunks)

    for base in range(0, len(actions), chunk_size):
        sub_statement = {key: value for key, value in statement.items() if key != statement_action}
        sub_statement[statement_action] = actions[base : base + chunk_size]  # noqa: E203
        yield sub_statement


def combine(policies: List[Policy]) -> List[Policy]:
    """Combine policy files into the smallest possible set of outputs."""

    new_policy = render(minify(policies))

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
    statements = new_policy.statement
    minimum_possible_policy_size = len(Policy().tiniest_json())
    max_number_of_commas = len(statements) - 2
    max_statement_size = (
        MAX_MANAGED_POLICY_SIZE - minimum_possible_policy_size - max_number_of_commas
    )

    packed_list = []
    for statement in statements:
        packed = tiniest_json(statement)
        if len(packed) > max_statement_size:
            for splitted in split_statement(statement, max_statement_size):
                packed_list.append(tiniest_json(splitted))
        else:
            packed_list.append(packed)

    statement_sets = optimizer.pack_statements(packed_list, max_statement_size, 10)

    policies = []
    for statement_set in statement_sets:
        # The splitting process above might have resulted in this policy having multiple statements
        # that could be merged back together. The easiest way to handle this is to create a new
        # policy as-is, then group its statements together into *another* new, optimized policy,
        # and emit that one.
        unmerged_policy = Policy()
        unmerged_policy.statement = [json.loads(statement) for statement in statement_set]
        merged_policy = render(minify([unmerged_policy]))
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

    # Write each of the files that file go into this policy set, and create a list of the filenames
    # we've written.
    output_filenames = []
    for i, policy in enumerate(policies, 1):
        output_path = output_dir / f"{base_name}_{i}.json"
        output_filenames.append(str(output_path))

        # Don't delete a file right after we create it.
        cleanup.discard(output_path)

        # Check if the on-disk file is identical to this one. If so, leave it alone so that we
        # don't have unnecessary churn in Git, Terraform, etc.
        #
        # We minimize churn by sorting collections whenever possible so that they're always output
        # in the same order if the original filenames change.
        try:
            on_disk_policy = json.loads(output_path.read_text())
        except FileNotFoundError:
            pass
        else:
            if policy == Policy.from_dict(on_disk_policy):
                continue

        output_path.write_text(policy.render())

    # Delete all of the pre-existing files, minus the ones we visited above.
    for old in cleanup:
        old.unlink()

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
