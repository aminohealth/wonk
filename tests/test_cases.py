"""Test the output of known inputs."""

import json
import pathlib

import pytest

from wonk import cli, policy

# Get the path to the "cases" directory that lives next to this module
CASE_BASE = pathlib.Path(__file__).parent / "cases"


@pytest.mark.parametrize("case_name", sorted(path.name for path in CASE_BASE.iterdir()))
def test_named_case(case_name, tmp_path):
    """Ensure that the named test case's inputs are combined into the expected outputs.

    Developer note: don't use Amazon's policies as test cases as there may be copyright issues
    with that.
    """

    test_base = CASE_BASE / case_name
    input_paths = (test_base / "inputs").glob("*.json")
    assert input_paths

    inputs = cli.policies_from_filenames(input_paths)
    combined = policy.combine(inputs)

    policy.write_policy_set(tmp_path, "output", combined)

    output_paths = (test_base / "outputs").glob("*.json")
    assert output_paths

    for path in output_paths:
        expected_output = json.loads(path.read_text())
        actual_output = json.loads((tmp_path / path.name).read_text())

        assert expected_output == actual_output
