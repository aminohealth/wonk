"""Test the wonk.policy module."""

import textwrap

import pytest

from wonk import exceptions, policy
from wonk.models import InternalStatement, Policy


def test_write_policy_set_doesnt_run_amok(tmp_path):
    """write_policy_set won't wipe your hard drive."""

    # Create test files 0..11.
    for i in range(12):
        (tmp_path / f"foo_{i}.json").write_text("fnord")

    with pytest.raises(exceptions.TooManyPoliciesError) as exc:
        policy.write_policy_set(
            tmp_path,
            "foo",
            [
                Policy(
                    statements=[InternalStatement({"Action": "something", "Resource": "spam"})]
                ),
                Policy(
                    statements=[
                        InternalStatement({"Action": "another something", "Resource": "eggs"})
                    ]
                ),
            ],
        )

    assert exc.value.policy_set == "foo"
    assert exc.value.policies == 12


def test_write_policy_leaves_expected_results(tmp_path):
    """write_policy_set leaves exactly the files we expect."""

    # Create test files 0..3.
    for i in range(4):
        (tmp_path / f"foo_{i}.json").write_text('{"what": "fnord"}')
        (tmp_path / f"foo_bar_{i}.json").write_text('{"what": "fnord"}')

    written = policy.write_policy_set(
        tmp_path,
        "foo",
        [
            Policy(statements=[InternalStatement({"Action": "do", "Resource": "something"})]),
            Policy(
                statements=[
                    InternalStatement({"Action": "ignore", "NotResource": "another something"})
                ]
            ),
        ],
    )

    assert written == [f"{tmp_path}/foo_1.json", f"{tmp_path}/foo_2.json"]

    # foo_0 and foo_3 should have been deleted, and all of the foo_bar_N files should have been
    # left alone.
    assert {str(_) for _ in tmp_path.glob("*")} == {
        f"{tmp_path}/foo_1.json",
        f"{tmp_path}/foo_2.json",
        f"{tmp_path}/foo_bar_0.json",
        f"{tmp_path}/foo_bar_1.json",
        f"{tmp_path}/foo_bar_2.json",
        f"{tmp_path}/foo_bar_3.json",
    }

    # foo_1.json and foo_2.json have their supplied contents.
    assert (tmp_path / "foo_1.json").read_text() == textwrap.dedent(
        """\
        {
            "Version": "2012-10-17",
            "Id": "20feeba11f0d5a5d4f3f88f590c3a6e9",
            "Statement": [
                {
                    "Action": "do",
                    "Resource": "something"
                }
            ]
        }"""
    )
    assert (tmp_path / "foo_2.json").read_text() == textwrap.dedent(
        """\
        {
            "Version": "2012-10-17",
            "Id": "bd4d3789ad19090802df8fc64ac7ae28",
            "Statement": [
                {
                    "Action": "ignore",
                    "NotResource": "another something"
                }
            ]
        }"""
    )


def test_fetch_retrieves_policy(mocker):
    """fetch makes boto3 calls to retrieve the document, then caches it."""

    mock_cf = mocker.patch("wonk.policy.make_cache_file")
    mock_cf.return_value.read_text.side_effect = FileNotFoundError

    mock_gpv = mocker.patch("wonk.policy.aws.get_policy_version")
    mock_gpv.return_value = "pi"

    mock_gp = mocker.patch("wonk.policy.aws.get_policy")
    mock_gp.return_value = "{policy contents}"

    doc = policy.fetch(mocker.sentinel.client, "arn:hi:there/MyPolicy")

    assert doc is mock_gp.return_value
    mock_cf.return_value.read_text.assert_called_once_with()
    mock_cf.return_value.write_text.assert_called_once_with("{policy contents}")
    mock_gpv.assert_called_once_with(mocker.sentinel.client, "arn:hi:there/MyPolicy")
    mock_gp.assert_called_once_with(mocker.sentinel.client, "arn:hi:there/MyPolicy", "pi")


def test_policy_combine_small():
    """Combining one small policy does as expected."""

    policies = policy.combine(
        [Policy(statements=[InternalStatement({"Action": "Dance!", "Resource": ["Disco"]})])]
    )

    assert len(policies) == 1

    new_policy = policies[0]
    assert new_policy == Policy(
        version="2012-10-17",
        statements=[InternalStatement({"Action": "Dance!", "Resource": "Disco"})],
    )


def test_policy_combine_big():
    """Combining two big policies does as expected."""

    a_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.4)
    b_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.7)
    c_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.4)

    old_policies = [
        Policy(statements=[InternalStatement({"Action": [char * length], "NotResource": "spam"})])
        for char, length in [("a", a_len), ("b", b_len), ("c", c_len)]
    ]

    policies = policy.combine(old_policies)

    new_policy_1, new_policy_2 = policies

    assert new_policy_1 == Policy(
        version="2012-10-17",
        statements=[
            InternalStatement({"Action": ["a" * a_len, "c" * c_len], "NotResource": "spam"})
        ],
    )

    assert new_policy_2 == Policy(
        version="2012-10-17",
        statements=[InternalStatement({"Action": "b" * b_len, "NotResource": "spam"})],
    )


def test_split_statement():
    """Statements are correctly split into smaller chunks."""

    splitted = policy.split_statement(
        {"Action": ["a"] * 45 + ["b"] * 30 + ["c"] * 30 + ["d"] * 15}, 300
    )

    assert next(splitted) == {"Action": ["a"] * 30}
    assert next(splitted) == {"Action": ["a"] * 15 + ["b"] * 15}
    assert next(splitted) == {"Action": ["b"] * 15 + ["c"] * 15}
    assert next(splitted) == {"Action": ["c"] * 15 + ["d"] * 15}


def test_grouped_actions():
    """Simple statements are grouped as expected, even if their resources are written oddly."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": "*",
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["*", "*", "*"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    )

    changed, statements = policy.grouped_actions([policy1, policy2])
    assert changed
    assert len(statements) == 1
    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
        "Resource": "*",
        "Effect": "Allow",
    }


def test_grouped_actions_same_resources():
    """Simple statements with the same resources are grouped together."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["eggs", "spam", "bacon"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    )

    changed, statements = policy.grouped_actions([policy1, policy2])
    assert changed
    assert len(statements) == 1
    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
        "Resource": ["bacon", "eggs", "spam"],
        "Effect": "Allow",
    }


def test_grouped_actions_different_resources():
    """Statements with different resources don't get grouped together."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["spam", "eggs"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    )

    changed, statements = policy.grouped_actions([policy1, policy2])
    assert not changed
    assert len(statements) == 2

    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "spam"],
    }

    assert statements[1].as_json() == {
        "Action": ["SVC:Action2", "SVC:Action3"],
        "Effect": "Allow",
        "Resource": ["eggs", "spam"],
    }


def test_grouped_actions_notresources():
    """Statements with Resources don't get grouped with those with NotResources."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "NotResource": ["eggs", "spam", "bacon"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    )

    changed, statements = policy.grouped_actions([policy1, policy2])
    assert not changed
    assert len(statements) == 2

    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "eggs", "spam"],
    }

    assert statements[1].as_json() == {
        "Action": ["SVC:Action2", "SVC:Action3"],
        "Effect": "Allow",
        "NotResource": ["bacon", "eggs", "spam"],
    }


def test_grouped_resources():
    """Simple statements are grouped as expected."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["foo", "bar"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["bar", "baz"],
            "Action": ["SVC:Action2", "SVC:Action1"],
        }
    )

    changed, statements = policy.grouped_resources([policy1, policy2])
    assert changed
    assert len(statements) == 1
    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Resource": ["bar", "baz", "foo"],
        "Effect": "Allow",
    }


def test_grouped_resources_different_actions():
    """Statements with different actions don't get grouped together."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["spam", "eggs"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    )

    changed, statements = policy.grouped_resources([policy1, policy2])
    assert not changed
    assert len(statements) == 2

    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "spam"],
    }

    assert statements[1].as_json() == {
        "Action": ["SVC:Action2", "SVC:Action3"],
        "Effect": "Allow",
        "Resource": ["eggs", "spam"],
    }


def test_grouped_resources_notactions():
    """Statements with Actions don't get grouped with those with NotActions."""

    policy1 = policy.InternalStatement(
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    )

    policy2 = policy.InternalStatement(
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "NotAction": ["SVC:Action1", "SVC:Action2"],
        }
    )

    changed, statements = policy.grouped_resources([policy1, policy2])
    assert not changed
    assert len(statements) == 2

    assert statements[0].as_json() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "eggs", "spam"],
    }

    assert statements[1].as_json() == {
        "NotAction": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "eggs", "spam"],
    }
