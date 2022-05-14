"""Test the wonk.models module."""

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


def test_canonicalize_actions_removes_dupes():
    """Duplicate actions are removed."""

    # This is vacuously true as sets are deduplicated by their nature.
    assert models.canonicalize_actions({"foo", "bar", "foo"}) == ["bar", "foo"]


def test_canonicalize_actions_removes_servicewide_shadows():
    """Shadowed actions at the service level are removed."""

    assert models.canonicalize_actions({"svc:spam", "svc:*", "svc:eggs"}) == ["svc:*"]


def test_canonicalize_actions_removes_prefixed_shadows():
    """Shadowed actions whose names match wildcards with prefixes are removed."""

    assert models.canonicalize_actions({"svc:GetSomething", "svc:PutSomething", "svc:Get*"}) == [
        "svc:Get*",
        "svc:PutSomething",
    ]


def test_canonicalize_actions_removes_prefixed_shadows_multiple_wildcards():
    """Shadowed actions in sets with with multiple wildcards are pruned correctly."""

    assert (
        models.canonicalize_actions(
            {
                "s3:Get*",
                "s3:*",
                "s3:List*",
                "s3:Head*",
            }
        )
        == ["s3:*"]
    )


def test_canonicalize_actions_removes_prefixed_shadows_inconvenient_order():
    """The order of actions doesn't matter when pruning shadowed actions."""

    assert (
        models.canonicalize_actions(
            {
                "s3:GetFoo",
                "s3:GetFoo*",
            }
        )
        == ["s3:GetFoo*"]
    )


def test_canonicalize_actions_removes_prefixed_shadows_ignore_case():
    """Wildcard actions which differ only in case are treated as the same action."""

    assert (
        models.canonicalize_actions(
            {
                "s3:getfoo*",
                "s3:GetFoo*",
            }
        )
        == ["s3:GetFoo*"]
    )


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

    assert (
        models.canonicalize_resources(
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
        )
        == ["arn:a*", "arn:ba*", "arn:bb", "arn:bc", "arn:something*"]
    )


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

    assert models.InternalStatement(statement).grouping_for_actions() == expected


def test_sorting_key():
    """Ensure sorting keys have the expected shape and are ordered correctly."""

    statement1 = models.InternalStatement(STATEMENT_WITH_CONDITION)

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

    statement2 = models.InternalStatement(STATEMENT_DENY_NOTRESOURCE)

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

    statement3 = models.InternalStatement(STATEMENT_SIMPLE)

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
    statement1 = models.InternalStatement(STATEMENT_WITH_CONDITION)

    # This will come third because it has a NotAction, and a specific NotResource.
    statement2 = models.InternalStatement(STATEMENT_DENY_NOTRESOURCE)

    # This will come first because it's the simplest statement.
    statement3 = models.InternalStatement(STATEMENT_SIMPLE)

    assert sorted((statement1, statement2, statement3), key=lambda obj: obj.sorting_key()) == [
        statement3,
        statement1,
        statement2,
    ]


def test_policy_render():
    """A rendered policy looks like we'd expect it to."""

    # This should be output last because it's just some random statement.
    statement_1 = models.InternalStatement(
        {
            "Effect": "Deny",
            "Action": {"SVC:BadAction1", "SVC:BadAction4"},
            "Resource": "*",
        }
    )

    # This should be output second because it's the NotAction version of the minimal statement.
    statement_2 = models.InternalStatement(
        {
            "Effect": "Allow",
            "NotAction": {"SVC:OtherAction1", "SVC:OtherAction5"},
            "Resource": "*",
        }
    )

    # This should be output first because it's the minimal statement.
    statement_3 = models.InternalStatement(
        {
            "Effect": "Allow",
            "Action": {"SVC:Action1", "SVC:Action2", "SVC:Action3"},
            "Resource": "*",
        }
    )

    rendered = models.Policy(statements=[statement_1, statement_2, statement_3])

    assert rendered == models.Policy(
        statements=[
            models.InternalStatement(
                {
                    "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
                    "Effect": "Allow",
                    "Resource": "*",
                }
            ),
            models.InternalStatement(
                {
                    "Action": ["SVC:BadAction1", "SVC:BadAction4"],
                    "Effect": "Deny",
                    "Resource": "*",
                }
            ),
            models.InternalStatement(
                {
                    "Effect": "Allow",
                    "NotAction": ["SVC:OtherAction1", "SVC:OtherAction5"],
                    "Resource": "*",
                }
            ),
        ]
    )
