"""Test the wonk.models module."""

import json
from string import ascii_lowercase

import pytest

from wonk import models

STATEMENT_SIMPLE = {
    "Action": {"SVC:Action1", "SVC:Action2", "SVC:Action3", "SVC:Action4", "SVC:Action4"},
    "Effect": "Allow",
    "Resource": "*",
}

STATEMENT_NOTACTION = {
    "Effect": "Allow",
    "NotAction": {"SVC:OtherAction1", "SVC:OtherAction5"},
    "Resource": "*",
}


STATEMENT_WITH_CONDITION = {
    "Action": {"SVC:Action1", "SVC:Action2", "SVC:Action3"},
    "Effect": "Allow",
    "Resource": "*",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Condition": {
        "StringEquals": {
            "iam:AWSServiceName": [
                "service1",
                "service3",
                "service2",
            ]
        }
    },
}

STATEMENT_DENY_NOTRESOURCE = {
    "NotAction": {"SVC:BadAction1", "SVC:BadAction4"},
    "Effect": "Deny",
    "NotResource": "some_resource",
}


def test_collect_wildcard_matches_removes_dupes():
    """Duplicate actions are removed."""

    # This is vacuously true as sets are deduplicated by their nature.
    assert models.collect_wildcard_matches({"foo", "bar", "foo"}) == ["bar", "foo"]


def test_collect_wildcard_matches_removes_servicewide_shadows():
    """Shadowed actions at the service level are removed."""

    assert models.collect_wildcard_matches({"svc:spam", "svc:*", "svc:eggs"}) == ["svc:*"]


def test_collect_wildcard_matches_removes_prefixed_shadows():
    """Shadowed actions whose names match wildcards with prefixes are removed."""

    assert models.collect_wildcard_matches(
        {"svc:GetSomething", "svc:PutSomething", "svc:Get*"}
    ) == [
        "svc:Get*",
        "svc:PutSomething",
    ]


def test_collect_wildcard_matches_removes_prefixed_shadows_multiple_wildcards():
    """Shadowed actions in sets with with multiple wildcards are pruned correctly."""

    assert models.collect_wildcard_matches(
        {
            "s3:Get*",
            "s3:*",
            "s3:List*",
            "s3:Head*",
        }
    ) == ["s3:*"]


def test_collect_wildcard_matches_removes_prefixed_shadows_inconvenient_order():
    """The order of actions doesn't matter when pruning shadowed actions."""

    assert models.collect_wildcard_matches(
        {
            "s3:GetFoo",
            "s3:GetFoo*",
        }
    ) == ["s3:GetFoo*"]


def test_collect_wildcard_matches_removes_prefixed_shadows_ignore_case():
    """Wildcard actions which differ only in case are treated as the same action."""

    assert models.collect_wildcard_matches(
        {
            "s3:getfoo*",
            "s3:GetFoo*",
        }
    ) == ["s3:GetFoo*"]


def test_canonicalize_resources_all():
    """If resources contain "*", then that's the only one that counts."""

    assert models.canonicalize_resources({"foo", "bar", "*"}) == "*"


def test_canonicalize_resources_one():
    """If there's only one resource, return it."""

    assert models.canonicalize_resources({"foo"}) == "foo"


def test_canonicalize_resources_just_strings():
    """If all the resources are strings without wildcards, return them in order."""

    assert models.canonicalize_resources({"foo", "bar", "baz"}) == ["bar", "baz", "foo"]


def test_canonicalize_resources_wildcards():
    """If any of the resources are strings with wildcards, remove the shadowed resources."""

    assert models.canonicalize_resources(
        {
            "arn:something42",
            "arn:something23",
            "arn:something*",
            "arn:a*",
            "arn:aa",
            "arn:aaa",
            "arn:ba*",
            "arn:bad",
            "arn:bb",
            "arn:bc",
        }
    ) == ["arn:a*", "arn:ba*", "arn:bb", "arn:bc", "arn:something*"]


@pytest.mark.parametrize(
    "statement,expected",
    [
        (
            STATEMENT_SIMPLE,
            "['Action', ('Resource', '*'), ('Effect', 'Allow')]",
        ),
        (
            STATEMENT_DENY_NOTRESOURCE,
            "['NotAction', ('NotResource', 'some_resource'), ('Effect', 'Deny')]",
        ),
        (
            STATEMENT_NOTACTION,
            "['NotAction', ('Resource', '*'), ('Effect', 'Allow')]",
        ),
    ],
)
def test_grouping_for_actions(statement, expected):
    """Statements can be grouped by their expected key."""

    assert models.Statement(statement).grouping_for_actions() == expected


def test_sorting_key():
    """Ensure sorting keys have the expected shape and are ordered correctly."""

    statement1 = models.Statement(STATEMENT_WITH_CONDITION)

    sorting_key1 = statement1.sorting_key()

    assert sorting_key1 == (
        False,
        False,
        False,
        True,
        3,
        (
            '{"Condition":{"StringEquals":{"iam:AWSServiceName":["service1","service3","service2"]'
            '}},"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"}}'
        ),
        3,
        ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
    )

    statement2 = models.Statement(STATEMENT_DENY_NOTRESOURCE)

    sorting_key2 = statement2.sorting_key()

    assert sorting_key2 == (
        True,
        True,
        True,
        True,
        1,
        '{"Effect":"Deny"}',
        2,
        ["SVC:BadAction1", "SVC:BadAction4"],
    )

    statement3 = models.Statement(STATEMENT_SIMPLE)

    sorting_key3 = statement3.sorting_key()

    assert sorting_key3 == (
        False,
        False,
        False,
        False,
        1,
        '{"Effect":"Allow"}',
        4,
        ["SVC:Action1", "SVC:Action2", "SVC:Action3", "SVC:Action4"],
    )


def test_sorting_key_sorts_correctly():
    """The output of sorting_key is orderable in the expected way."""

    # This will come second because it has an Action, and Effect=Allow, and Resource=*.
    statement1 = models.Statement(STATEMENT_WITH_CONDITION)

    # This will come third because it has a NotAction, and a specific NotResource.
    statement2 = models.Statement(STATEMENT_DENY_NOTRESOURCE)

    # This will come first because it's the simplest statement.
    statement3 = models.Statement(STATEMENT_SIMPLE)

    assert sorted((statement1, statement2, statement3), key=lambda obj: obj.sorting_key()) == [
        statement3,
        statement1,
        statement2,
    ]


def test_policy_render():
    """A rendered policy looks like we'd expect it to."""

    # This should be output last because it's just some random statement.
    statement_1 = models.Statement(
        {
            "Effect": "Deny",
            "Action": {"SVC:BadAction1", "SVC:BadAction4"},
            "Resource": "*",
        }
    )

    # This should be output second because it's the NotAction version of the minimal statement.
    statement_2 = models.Statement(
        {
            "Effect": "Allow",
            "NotAction": {"SVC:OtherAction1", "SVC:OtherAction5"},
            "Resource": "*",
        }
    )

    # This should be output first because it's the minimal statement.
    statement_3 = models.Statement(
        {
            "Effect": "Allow",
            "Action": {"SVC:Action1", "SVC:Action2", "SVC:Action3"},
            "Resource": "*",
        }
    )

    rendered = models.Policy(statements=[statement_1, statement_2, statement_3]).render()

    assert json.loads(rendered) == {
        "Version": "2012-10-17",
        "Id": "2f2e3ef90177f911cf7382d4719a78b7",
        "Statement": [
            {
                "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
                "Effect": "Allow",
                "Resource": "*",
            },
            {
                "Action": ["SVC:BadAction1", "SVC:BadAction4"],
                "Effect": "Deny",
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "NotAction": ["SVC:OtherAction1", "SVC:OtherAction5"],
                "Resource": "*",
            },
        ],
    }


def test_split_statement():
    """Statements are correctly split into smaller chunks."""

    splitted = models.Statement({"Action": list(ascii_lowercase), "Resource": "foo"}).split(100)

    assert next(splitted) == {
        "Action": ["a", "b", "c", "d", "e", "f", "g", "h", "i"],
        "Resource": "foo",
    }
    assert next(splitted) == {
        "Action": ["j", "k", "l", "m", "n", "o", "p", "q", "r"],
        "Resource": "foo",
    }
    assert next(splitted) == {
        "Action": ["s", "t", "u", "v", "w", "x", "y", "z"],
        "Resource": "foo",
    }


def test_split_resource_statement():
    splitted = models.Statement({"Action": "foo", "Resource": list(ascii_lowercase)}).split_resource(100)

    assert next(splitted) == {
        "Action": ["foo"],
        "Resource": ["a", "b", "c", "d", "e", "f", "g", "h", "i"],
    }
    assert next(splitted) == {
        "Action": ["foo"],
        "Resource": ["j", "k", "l", "m", "n", "o", "p", "q", "r"],
    }
    assert next(splitted) == {
        "Action": ["foo"],
        "Resource": ["s", "t", "u", "v", "w", "x", "y", "z"],
    }


def test_policy_from_dict_malformed_ok():
    """Malformed policies with dicts as their Statement are parsed correctly."""

    rendered = models.Policy.from_dict(
        {"Statement": {"Effect": "Deny", "Action": "twirl", "Resource": "widget"}}
    ).render()

    assert json.loads(rendered) == {
        "Version": "2012-10-17",
        "Id": "2d8f6cb90c80585ade0580022df5c75a",
        "Statement": [{"Effect": "Deny", "Action": "twirl", "Resource": "widget"}],
    }
