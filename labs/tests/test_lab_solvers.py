"""Test suite for automated lab solvers and walkthroughs."""

import pytest
from labs.solvers import SOLVERS, get_lab_solver, run_lab_solve_step

def test_all_20_labs_have_solvers():
    """Check that all 20 labs have defined solvers."""
    assert len(SOLVERS) == 20
    for i in range(1, 21):
        key = str(i).zfill(2)
        assert key in SOLVERS, f"Lab {key} is missing a solver definition"
        solver = SOLVERS[key]
        assert "title" in solver
        assert len(solver["steps"]) >= 1

def test_solver_step_structure():
    """Verify each step has target, explanation, payload, defense, and output."""
    for lab_id, solver in SOLVERS.items():
        for step in solver["steps"]:
            assert "step" in step
            assert "name" in step
            assert "target" in step
            assert "poc_explanation" in step
            assert "exploit_payload" in step
            assert "defense" in step
            assert "sample_output" in step

def test_run_lab_solve_step():
    """Test solver execution simulation."""
    res1 = run_lab_solve_step("01", 1)
    assert res1["success"] is True
    assert "SQL Injection" in res1["name"]
    assert "FLAG{" in res1["output"]

    res19 = run_lab_solve_step("19", 1)
    assert res19["success"] is True
    assert "Frida" in res19["name"]
    assert "FLAG{" in res19["output"]

    res20 = run_lab_solve_step("20", 2)
    assert res20["success"] is True
    assert "HEVD" in res20["name"]
    assert "FLAG{" in res20["output"]

def test_invalid_lab_solver():
    """Test invalid lab handling."""
    res = run_lab_solve_step("99", 1)
    assert res["success"] is False
