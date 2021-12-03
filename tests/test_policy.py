"""Test the wonk.policy module."""

import pytest

from wonk import exceptions, policy
from wonk.constants import PolicyKey


def test_write_policy_set_doesnt_run_amok(tmp_path):
    """write_policy_set won't wipe your hard drive."""

    # Create test files 0..11.
    for i in range(12):
        (tmp_path / f"foo_{i}.json").write_text("fnord")

    with pytest.raises(exceptions.TooManyPoliciesError) as exc:
        policy.write_policy_set(tmp_path, "foo", [{"foo": "something"}, {"bar": "something"}])

    assert exc.value.policy_set == "foo"
    assert exc.value.policies == 12


def test_write_policy_leaves_expected_results(tmp_path):
    """write_policy_set leaves exactly the files we expect."""

    # Create test files 0..3.
    for i in range(4):
        (tmp_path / f"foo_{i}.json").write_text('{"what": "fnord"}')
        (tmp_path / f"foo_bar_{i}.json").write_text('{"what": "fnord"}')

    written = policy.write_policy_set(
        tmp_path, "foo", [{"foo": "something"}, {"bar": "something"}]
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
    assert (
        (tmp_path / "foo_1.json").read_text()
        == """{
    "foo": "something"
}"""
    )
    assert (
        (tmp_path / "foo_2.json").read_text()
        == """{
    "bar": "something"
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

    policies = policy.combine([{"Statement": [{"Action": "Dance!", "Resource": ["Disco"]}]}])

    assert len(policies) == 1

    new_policy = policies[0]
    del new_policy["Id"]
    assert new_policy == {
        "Version": "2012-10-17",
        "Statement": [{"Action": "Dance!", "Resource": "Disco"}],
    }


def test_policy_combine_big():
    """Combining two big policies does as expected."""

    a_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.4)
    b_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.7)
    c_len = int(policy.MAX_MANAGED_POLICY_SIZE * 0.4)

    old_policies = [
        {"Statement": [{"Action": [char * length], "NotResource": "spam"}]}
        for char, length in [("a", a_len), ("b", b_len), ("c", c_len)]
    ]

    policies = policy.combine(old_policies)

    new_policy_1, new_policy_2 = policies

    del new_policy_1["Id"]

    assert new_policy_1 == {
        "Version": "2012-10-17",
        "Statement": [{"Action": ["a" * a_len, "c" * c_len], "NotResource": "spam"}],
    }

    del new_policy_2["Id"]

    assert new_policy_2 == {
        "Version": "2012-10-17",
        "Statement": [{"Action": "b" * b_len, "NotResource": "spam"}],
    }


def test_split_statement():
    """Statements are correctly split into smaller chunks."""

    splitted = policy.split_statement(
        {"Action": ["a"] * 45 + ["b"] * 30 + ["c"] * 30 + ["d"] * 15}, 300
    )

    assert next(splitted) == {"Action": ["a"] * 30}
    assert next(splitted) == {"Action": ["a"] * 15 + ["b"] * 15}
    assert next(splitted) == {"Action": ["b"] * 15 + ["c"] * 15}
    assert next(splitted) == {"Action": ["c"] * 15 + ["d"] * 15}


def test_grouped_statements():
    """Simple statements are grouped as expected, even if their resources are written oddly."""

    policy1 = policy.blank_policy()
    policy1[PolicyKey.STATEMENT] = [
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": "*",
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    ]

    policy2 = policy.blank_policy()
    policy2[PolicyKey.STATEMENT] = [
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["*", "*", "*"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    ]

    grouped_items = list(policy.grouped_statements([policy1, policy2]).items())
    assert len(grouped_items) == 1
    key, value = grouped_items[0]
    assert key == "['Action', ('Resource', '*'), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
        "Resource": "*",
        "Effect": "Allow",
    }


def test_grouped_statements_same_resources():
    """Simple statements with the same resources are grouped together."""

    policy1 = policy.blank_policy()
    policy1[PolicyKey.STATEMENT] = [
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    ]

    policy2 = policy.blank_policy()
    policy2[PolicyKey.STATEMENT] = [
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["eggs", "spam", "bacon"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    ]

    grouped = list(policy.grouped_statements([policy1, policy2]).items())
    assert len(grouped) == 1
    key, value = grouped[0]
    assert key == "['Action', ('Resource', ['bacon', 'eggs', 'spam']), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
        "Resource": ["bacon", "eggs", "spam"],
        "Effect": "Allow",
    }


def test_grouped_statements_diffent_resources():
    """Statements with different resources don't get grouped together."""

    policy1 = policy.blank_policy()
    policy1[PolicyKey.STATEMENT] = [
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    ]

    policy2 = policy.blank_policy()
    policy2[PolicyKey.STATEMENT] = [
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "Resource": ["spam", "eggs"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    ]

    grouped = list(policy.grouped_statements([policy1, policy2]).items())
    assert len(grouped) == 2

    key, value = grouped[0]
    assert key == "['Action', ('Resource', ['bacon', 'spam']), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "spam"],
    }

    key, value = grouped[1]
    assert key == "['Action', ('Resource', ['eggs', 'spam']), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action2", "SVC:Action3"],
        "Effect": "Allow",
        "Resource": ["eggs", "spam"],
    }


def test_grouped_statements_notresources():
    """Statements with Resources don't get grouped with those with NotResources."""

    policy1 = policy.blank_policy()
    policy1[PolicyKey.STATEMENT] = [
        {
            "Sid": "El",
            "Effect": "Allow",
            "Resource": ["spam", "bacon", "eggs"],
            "Action": ["SVC:Action1", "SVC:Action2"],
        }
    ]

    policy2 = policy.blank_policy()
    policy2[PolicyKey.STATEMENT] = [
        {
            "Sid": "Knee",
            "Effect": "Allow",
            "NotResource": ["eggs", "spam", "bacon"],
            "Action": ["SVC:Action2", "SVC:Action3"],
        }
    ]

    grouped = list(policy.grouped_statements([policy1, policy2]).items())
    assert len(grouped) == 2

    key, value = grouped[0]
    assert key == "['Action', ('Resource', ['bacon', 'eggs', 'spam']), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action1", "SVC:Action2"],
        "Effect": "Allow",
        "Resource": ["bacon", "eggs", "spam"],
    }

    key, value = grouped[1]
    assert key == "['Action', ('NotResource', ['bacon', 'eggs', 'spam']), ('Effect', 'Allow')]"
    assert value.render() == {
        "Action": ["SVC:Action2", "SVC:Action3"],
        "Effect": "Allow",
        "NotResource": ["bacon", "eggs", "spam"],
    }


def test_render():
    """A rendered policy looks like we'd expect it to."""

    # This should be output last because it's just some random statement.
    statement_1 = policy.InternalStatement(
        {
            "Effect": "Deny",
            "Action": {"SVC:BadAction1", "SVC:BadAction4"},
            "Resource": "*",
        }
    )

    # This should be output second because it's the NotAction version of the minimal statement.
    statement_2 = policy.InternalStatement(
        {
            "Effect": "Allow",
            "NotAction": {"SVC:OtherAction1", "SVC:OtherAction5"},
            "Resource": "*",
        }
    )

    # This should be output first because it's the minimal statement.
    statement_3 = policy.InternalStatement(
        {
            "Effect": "Allow",
            "Action": {"SVC:Action1", "SVC:Action2", "SVC:Action3"},
            "Resource": "*",
        }
    )

    statement_set = {
        statement.grouping_key(): statement
        for statement in (statement_1, statement_2, statement_3)
    }

    rendered = policy.render(statement_set)
    rendered.pop("Id", None)

    assert rendered == {
        "Statement": [
            {
                "Action": ["SVC:Action1", "SVC:Action2", "SVC:Action3"],
                "Effect": "Allow",
                "Resource": "*",
            },
            {"Action": ["SVC:BadAction1", "SVC:BadAction4"], "Effect": "Deny", "Resource": "*"},
            {
                "Effect": "Allow",
                "NotAction": ["SVC:OtherAction1", "SVC:OtherAction5"],
                "Resource": "*",
            },
        ],
        "Version": "2012-10-17",
    }
