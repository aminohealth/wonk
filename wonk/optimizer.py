"""Use a solver to pack as many statements as possible into as few policies as possible."""

from typing import List

from ortools.linear_solver import pywraplp  # type: ignore

from wonk.exceptions import UnpackableStatementsError


def pack_statements(packed: List[str], max_statement_size: int, bins: int) -> List[List[str]]:
    """Use Google's solver to pack the statements into a minimal number of bins.

    This code is borrowed from the example code at
    https://developers.google.com/optimization/bin/bin_packing .
    """

    # Create the mip solver with the SCIP backend.
    solver = pywraplp.Solver.CreateSolver("SCIP")

    # Variables
    # x[i, j] = 1 if item i is packed in bin j.
    x = {}  # pylint: disable=invalid-name
    for i in range(len(packed)):
        for j in range(bins):
            x[(i, j)] = solver.IntVar(0, 1, f"x_{i}_{j}")

    # y[j] = 1 if bin j is used.
    y = {}  # pylint: disable=invalid-name
    for j in range(bins):
        y[j] = solver.IntVar(0, 1, f"y[{j}]")

    # Constraints
    # Each item must be in exactly one bin.
    for i in range(len(packed)):
        solver.Add(sum(x[i, j] for j in range(bins)) == 1)

    # The amount packed in each bin cannot exceed its capacity.
    for j in range(bins):
        solver.Add(
            sum(x[(i, j)] * len(item) for i, item in enumerate(packed))
            <= y[j] * max_statement_size
        )

    # Objective: minimize the number of bins used.
    solver.Minimize(solver.Sum([y[j] for j in range(bins)]))

    status = solver.Solve()

    if status != pywraplp.Solver.OPTIMAL:
        raise UnpackableStatementsError

    results = []
    for j in range(bins):
        if y[j].solution_value() != 1:
            continue
        bin_statements = []
        for i, item in enumerate(packed):
            if x[i, j].solution_value() > 0:
                bin_statements.append(item)
        if bin_statements:
            results.append(bin_statements)

    return results
