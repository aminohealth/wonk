"""Test the wonk.config module."""

import pytest

from wonk import config, exceptions


def test_parse_config():
    """Good configuration data yields a good Config object."""

    conf = config.parse_config(
        {
            "policy_sets": {
                "Spam": {
                    "managed": ["Foo"],
                    "local": ["file1"],
                },
                "Eggs": {
                    "managed": ["Bar"],
                    "inherits": ["Spam"],
                },
                "Qux": {},
            }
        }
    )

    assert conf.policy_sets["Spam"].managed == ["Foo"]
    assert conf.policy_sets["Spam"].local == ["file1"]
    assert not conf.policy_sets["Spam"].inherits

    assert conf.policy_sets["Eggs"].managed == ["Bar", "Foo"]
    assert conf.policy_sets["Eggs"].local == ["file1"]
    assert conf.policy_sets["Eggs"].inherits == ["Spam"]

    assert not conf.policy_sets["Qux"].managed
    assert not conf.policy_sets["Qux"].local
    assert not conf.policy_sets["Qux"].inherits


def test_parse_config_minimal():
    """A minimal config defines nothing."""

    conf = config.parse_config({})

    assert not conf.policy_sets


def test_parse_policy_sets_misspelling():
    """Fail if a policy set's parent doesn't actually exist."""

    with pytest.raises(exceptions.UnknownParentError) as exc:
        config.parse_config(
            {
                "policy_sets": {
                    "Spam": {
                        "managed": ["Foo"],
                        "local": ["file1"],
                    },
                    "Eggs": {
                        "managed": ["Bar"],
                        "inherits": ["Spammers"],
                    },
                }
            }
        )

    assert exc.value.args == ("Eggs", "Spammers")
