"""Test the wonk.optimizer module."""

import pytest

from wonk import exceptions, optimizer


def test_pack_statements():
    """The statement packer is able to solve the knapsack problem."""

    packed = optimizer.pack_statements(["a" * 35, "b" * 45, "c" * 55, "d" * 65], 100, 2)

    assert packed == [
        ["b" * 45, "c" * 55],
        ["a" * 35, "d" * 65],
    ]


def test_unpackable_statements():
    """The statement packer isn't all-powerful."""

    with pytest.raises(exceptions.UnpackableStatementsError):
        optimizer.pack_statements(["a" * 35, "b" * 45, "c" * 55, "d" * 65], 99, 2)
