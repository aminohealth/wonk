"""Interact with AWS."""

import json
from functools import lru_cache

import boto3


@lru_cache()
def iam_client(*, profile: str = None):
    """Return a boto3 IAM client."""

    session = boto3.session.Session(profile_name=profile)
    return session.client("iam")


def arn_for(name: str) -> str:
    """Return the ARN that probably holds the named policy."""

    return f"arn:aws:iam::aws:policy/{name}"


def name_for(arn: str) -> str:
    """Return the policy name for the ARN."""

    return arn.split("/")[-1]


def get_policy_version(client, arn: str) -> str:
    """Get the default version of the policy with this ARN.

    This is opposite of the AWS API name where `get_policy` gives you information about a policy's
    current version but not the policy's contents.
    """

    policy_info = client.get_policy(PolicyArn=arn)
    return policy_info["Policy"]["DefaultVersionId"]


def get_policy(client, arn: str, version: str) -> str:
    """Get the contents of this version of the policy with this ARN.

    This is opposite of the AWS API name where `get_policy_version` returns the policy's contents,
    not just its version.
    """

    policy = client.get_policy_version(PolicyArn=arn, VersionId=version)
    return json.dumps(policy["PolicyVersion"]["Document"], indent=4)
