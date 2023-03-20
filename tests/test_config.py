"""Test the wonk.config module."""

import pytest

from wonk import config, exceptions


def test_parse_config():
    """Good configuration data yields a good Config object."""

    conf = config.parse_config(
        {
            "policy_sets": {
                "Poultry": {
                    "abstract": True,
                    "managed": ["Squawk"],
                    "local": ["file2"],
                },
                "Spam": {
                    "managed": ["Foo"],
                    "local": ["file1"],
                },
                "Eggs": {
                    "managed": ["Bar"],
                    "inherits": ["Poultry", "Spam"],
                },
                "Qux": {},
            }
        }
    )

    assert conf.policy_sets["Poultry"].managed == ["Squawk"]
    assert conf.policy_sets["Poultry"].local == ["file2"]
    assert conf.policy_sets["Poultry"].abstract

    assert conf.policy_sets["Spam"].managed == ["Foo"]
    assert conf.policy_sets["Spam"].local == ["file1"]
    assert not conf.policy_sets["Spam"].inherits
    assert not conf.policy_sets["Spam"].abstract

    # The order of 'managed' and 'local' policies is stable based on the order
    # parent policies are inherited. Since 'Poultry' is inherited first, its
    # managed and local policies come first in these lists.
    assert conf.policy_sets["Eggs"].managed == ["Bar", "Squawk", "Foo"]
    assert conf.policy_sets["Eggs"].local == ["file2", "file1"]
    assert conf.policy_sets["Eggs"].inherits == ["Poultry", "Spam"]
    assert not conf.policy_sets["Eggs"].abstract

    assert not conf.policy_sets["Qux"].managed
    assert not conf.policy_sets["Qux"].local
    assert not conf.policy_sets["Qux"].inherits
    assert not conf.policy_sets["Qux"].abstract


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
