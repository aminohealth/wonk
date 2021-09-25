"""Manage AWS policies."""

import copy
import json
import math
import pathlib
import re
import uuid
from typing import Dict, Generator, List, Union

from xdg import xdg_cache_home

from wonk import aws, exceptions, optimizer
from wonk.constants import ACTION_KEYS, JSON_ARGS, MAX_MANAGED_POLICY_SIZE, PolicyKey
from wonk.models import InternalStatement, Policy, Statement, which_type

POLICY_CACHE_DIR = xdg_cache_home() / "com.amino.wonk" / "policies"


def grouped_statements(policies: List[Policy]) -> Dict[str, InternalStatement]:
    """Merge the policies' statements by their zone of effect."""

    statement_sets: Dict[str, InternalStatement] = {}

    for policy in policies:
        # According to the policy language grammar (see
        # https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html) the
        # Statement key should have a list of statements, and indeed that's almost always the case.
        # Some of Amazon's own policies (see AWSCertificateManagerReadOnly) have a Statement key
        # that points to a dict instead of a list of dicts. This ensures that we're always dealing
        # with a list of statements.
        statements = policy[PolicyKey.STATEMENT]
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            internal_statement = InternalStatement(statement)
            group = internal_statement.grouping_key()

            try:
                existing_item = statement_sets[group]
            except KeyError:
                statement_sets[group] = internal_statement
            else:
                existing_item.action_value |= internal_statement.action_value

    return statement_sets


def blank_policy() -> Policy:
    """Return the skeleton of a policy with no statments."""

    return {
        PolicyKey.VERSION: "2012-10-17",
        PolicyKey.ID: uuid.uuid4().hex,
        PolicyKey.STATEMENT: [],
    }


def render(statement_sets: Dict[str, InternalStatement]) -> Policy:
    """Turn the contents of the statement sets into a valid AWS policy."""

    policy = blank_policy()

    # Sort everything that can be sorted. This ensures that separate runs of the program generate
    # the same outputs, which 1) makes `git diff` happy, and 2) lets us later check to see if we're
    # actually updating a policy that we've written out, and if so, skip writing it again (with a
    # new `Id` key).
    for internal_statement in sorted(statement_sets.values(), key=lambda obj: obj.sorting_key()):
        policy[PolicyKey.STATEMENT].append(internal_statement.render())

    return policy


def packed_json(data: Policy, max_size: int) -> str:
    """Return the most aesthetic representation of the data that fits in the size."""
    for args in JSON_ARGS:
        packed = json.dumps(data, sort_keys=True, **args)
        if len(packed) <= max_size:
            return packed

    raise exceptions.UnshrinkablePolicyError(
        f"Unable to shrink the data into into {max_size} characters: {data!r}"
    )


def tiniest_json(data: Union[Policy, Statement]) -> str:
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

    new_policy = render(grouped_statements(policies))

    # Simplest case: we're able to squeeze everything into a single file. This is the ideal.
    try:
        packed_json(new_policy, MAX_MANAGED_POLICY_SIZE)
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
    statements = new_policy[PolicyKey.STATEMENT]
    minimum_possible_policy_size = len(tiniest_json(blank_policy()))
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
        unmerged_policy = blank_policy()
        unmerged_policy[PolicyKey.STATEMENT] = [
            json.loads(statement) for statement in statement_set
        ]
        merged_policy = render(grouped_statements([unmerged_policy]))
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
            if policies_are_identical(on_disk_policy, policy):
                continue

        output_path.write_text(packed_json(policy, MAX_MANAGED_POLICY_SIZE))

    # Delete all of the pre-existing files, minus the ones we visited above.
    for old in cleanup:
        old.unlink()

    return output_filenames


def policies_are_identical(old_policy: Policy, new_policy: Policy) -> bool:
    """Return True if the old and new policies are identical other than their IDs."""

    old_policy, new_policy = copy.deepcopy(old_policy), copy.deepcopy(new_policy)

    try:
        # If the on-disk policy is missing the `Id` key, then the policy's been altered and we know
        # it's no longer identical to the new one.
        del old_policy[PolicyKey.ID]
    except KeyError:
        return False

    new_policy.pop(PolicyKey.ID, None)

    # We minimize churn by sorting collections whenever possible so that they're always output in
    # the same order if the input policies haven't changed. That's better (and in the long run,
    # easier) than implementing an order-insensitive comparison here because it also keeps the
    # on-disk policy stable between runs. This makes git happy.

    return old_policy == new_policy


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
