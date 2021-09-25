#!/usr/bin/env python

"""The Policy Wonk helps manage your AWS IAM policies."""

import argparse
import json
import pathlib
import sys

from wonk.aws import arn_for, iam_client, name_for
from wonk.config import load_config
from wonk.policy import combine, fetch, write_policy_set


def command_line_build(args):
    """Create an output file from a configuration."""

    full_config = load_config(args.config)

    if not full_config.policy_sets:
        print("No policy sets are configured.")
        sys.exit(1)

    if args.all:
        policy_sets = full_config.policy_sets.keys()
    else:
        policy_sets = args.policy_set

    for policy_set in policy_sets:
        config = full_config.policy_sets[policy_set]
        input_filenames = []

        for managed_policy in config.managed:
            if managed_policy.startswith("arn:"):
                arn = managed_policy
                name = name_for(arn)
            else:
                name = managed_policy
                arn = arn_for(name)

            filename = f"managed/{name}.json"
            if not pathlib.Path(filename).is_file():
                print(f"Fetching missing managed policy {managed_policy}")
                pathlib.Path(filename).write_text(fetch(iam_client(profile=args.profile), arn))
            input_filenames.append(filename)

        for local_policy in config.local:
            input_filenames.append(f"local/{local_policy}.json")

        policies = [json.loads(pathlib.Path(filename).read_text()) for filename in input_filenames]
        output_filenames = write_policy_set(args.path, policy_set, combine(policies))

        print()
        print(f"Created the following files for policy set {policy_set}:")
        print()
        for filename in output_filenames:
            print(f"- {filename}")
        print()


def command_line_combine(args):
    """Combine multiple policies into a small number of policies."""

    policies = [json.loads(pathlib.Path(filename).read_text()) for filename in args.policy]
    filenames = write_policy_set(args.path, args.policy_set, combine(policies))

    print("Created the following files:")
    print()
    for filename in filenames:
        print(f"- {filename}")


def command_line_fetch(args):
    """Fetch and AWS policy by ARN and print its contents."""

    if args.name is None:
        arn = args.arn
    else:
        arn = arn_for(args.name)

    print(fetch(iam_client(profile=args.profile), arn, args.force))


def handle_command_line():
    """Process the command line arguments."""

    parser = argparse.ArgumentParser(description=__doc__)

    subparsers = parser.add_subparsers()

    # Create the `wonk build` parser
    builder = subparsers.add_parser("build", help=command_line_build.__doc__)
    builder.add_argument(
        "--config",
        "-c",
        type=pathlib.Path,
        default=pathlib.Path("wonk.yaml"),
        help="Name of the YAML config file. Default: %(default)s",
    )
    builder.add_argument(
        "--path",
        type=pathlib.Path,
        default=pathlib.Path("combined"),
        help="Name of the directory to write to. Default: %(default)s",
    )
    group = builder.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--policy-set",
        "-p",
        action="append",
        help=("Name a configured policy set to build. May be given multiple times."),
    )
    group.add_argument("--all", action="store_true", help="Build all configured policy sets.")
    builder.add_argument("--profile", help="Optional IAM profile to authenticate with")
    builder.set_defaults(func=command_line_build)

    # Create the `wonk combine` parser
    combiner = subparsers.add_parser("combine", help=command_line_combine.__doc__)
    combiner.add_argument(
        "--path",
        type=pathlib.Path,
        default=pathlib.Path("."),
        help="Name of the directory to write to. Default: %(default)s",
    )
    combiner.add_argument(
        "--policy-set", "-p", required=True, help="Name of the policy set to create"
    )
    combiner.add_argument("policy", nargs="+", help="Filename of a policy to merge")
    combiner.set_defaults(func=command_line_combine)

    # Create the `wonk fetch` parser
    fetcher = subparsers.add_parser("fetch", help=command_line_fetch.__doc__)
    group = fetcher.add_mutually_exclusive_group(required=True)
    group.add_argument("--arn", help="ARN of a policy to fetch from AWS")
    group.add_argument("--name", help="Name of a policy to fetch from AWS")
    fetcher.add_argument("--force", action="store_true", help="Fetch the policy even if cached")
    fetcher.add_argument("--profile", help="Optional IAM profile to authenticate with")
    fetcher.set_defaults(func=command_line_fetch)

    args = parser.parse_args()

    try:
        func = args.func
    except AttributeError:
        parser.print_help()
    else:
        func(args)


if __name__ == "__main__":
    handle_command_line()
