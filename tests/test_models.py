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

    assert models.canonicalize_actions(["foo", "bar", "foo"]) == ["bar", "foo"]


def test_canonicalize_actions_removes_servicewide_shadows():
    """Shadowed actions at the service level are removed."""

    assert models.canonicalize_actions(["svc:spam", "svc:*", "svc:eggs"]) == ["svc:*"]


def test_canonicalize_actions_removes_prefixed_shadows():
    """Shadowed actions whose names match wildcards with prefixes are removed."""

    assert models.canonicalize_actions(["svc:GetSomething", "svc:PutSomething", "svc:Get*"]) == [
        "svc:Get*",
        "svc:PutSomething",
    ]


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
def test_grouping_key(statement, expected):
    """Statements can be grouped by their expected key."""

    assert models.InternalStatement(statement).grouping_key() == expected


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
