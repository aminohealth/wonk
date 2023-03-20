"""Wonk CLI command unit tests."""

from argparse import Namespace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import yaml

from wonk.cli import command_line_build
from wonk.models import Policy


@pytest.fixture
def wonk_tempdir():
    """A temporary directory setup to run wonk commands."""

    with TemporaryDirectory() as tmpdir:
        dir_path = Path(tmpdir)

        for subfolder in ["managed", "local", "combined"]:
            subfolder_path = dir_path / subfolder
            subfolder_path.mkdir()

        yield dir_path


@pytest.fixture
def wonk_yaml_abstract(wonk_tempdir):
    """A wonk.yaml file with an abstract policy set."""

    config = {
        "policy_sets": {
            "PolicyA": {
                "abstract": True,
            },
            "PolicyB": {
                "inherits": ["PolicyA"],
            },
        }
    }

    wonk_yaml_path = wonk_tempdir / "wonk.yaml"
    wonk_yaml_path.write_text(yaml.dump(config))
    return wonk_yaml_path


def test_command_line_build__abstract(wonk_tempdir, wonk_yaml_abstract, mocker):
    """Should skip building abstract policy sets."""

    mock_write = mocker.patch("wonk.cli.write_policy_set")

    args = Namespace(
        config=wonk_yaml_abstract,
        path=wonk_tempdir,  # cwd
        all=True,
    )

    command_line_build(args)

    # Wonk does not attempt to build abstract policy set PolicyA
    expected_combined = [Policy(statements=[], version="2012-10-17")]
    mock_write.assert_called_once_with(wonk_tempdir, "PolicyB", expected_combined)
