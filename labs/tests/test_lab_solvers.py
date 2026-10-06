"""Test suite for automated lab solvers and walkthroughs."""

import pytest
from labs.solvers import SOLVERS, get_lab_solver, run_lab_solve_step

def test_all_37_labs_have_solvers():
    """Check that all 37 labs have defined solvers."""
    assert len(SOLVERS) == 37
    for i in range(1, 38):
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

    res21 = run_lab_solve_step("21", 1)
    assert res21["success"] is True
    assert "CAN" in res21["name"]
    assert "FLAG{" in res21["output"]

    res22 = run_lab_solve_step("22", 1)
    assert res22["success"] is True
    assert "BOLA" in res22["name"]
    assert "FLAG{" in res22["output"]

    res23 = run_lab_solve_step("23", 1)
    assert res23["success"] is True
    assert "Sysmon" in res23["name"]
    assert "FLAG{" in res23["output"]

    res24 = run_lab_solve_step("24", 1)
    assert res24["success"] is True
    assert "AFL++" in res24["name"]
    assert "FLAG{" in res24["output"]

    res25 = run_lab_solve_step("25", 1)
    assert res25["success"] is True
    assert "RAG" in res25["name"]
    assert "FLAG{" in res25["output"]

    res26 = run_lab_solve_step("26", 1)
    assert res26["success"] is True
    assert "PE" in res26["name"]
    assert "FLAG{" in res26["output"]

    res27 = run_lab_solve_step("27", 1)
    assert res27["success"] is True
    assert "PMKID" in res27["name"]
    assert "FLAG{" in res27["output"]

    res28 = run_lab_solve_step("28", 1)
    assert res28["success"] is True
    assert "SNMP" in res28["name"]
    assert "FLAG{" in res28["output"]

    res29 = run_lab_solve_step("29", 1)
    assert res29["success"] is True
    assert "ESC1" in res29["name"]
    assert "FLAG{" in res29["output"]

    res30 = run_lab_solve_step("30", 1)
    assert res30["success"] is True
    assert "Ghidra" in res30["name"]
    assert "FLAG{" in res30["output"]

    res31 = run_lab_solve_step("31", 1)
    assert res31["success"] is True
    assert "Redirect" in res31["name"]
    assert "FLAG{" in res31["output"]

    res32 = run_lab_solve_step("32", 1)
    assert res32["success"] is True
    assert "Exact Prefix" in res32["name"]
    assert "FLAG{" in res32["output"]

    res33 = run_lab_solve_step("33", 1)
    assert res33["success"] is True
    assert "KISA" in res33["name"]
    assert "FLAG{" in res33["output"]

    res34 = run_lab_solve_step("34", 1)
    assert res34["success"] is True
    assert "Shodan" in res34["name"]
    assert "FLAG{" in res34["output"]

    res35 = run_lab_solve_step("35", 1)
    assert res35["success"] is True
    assert "PassRole" in res35["name"]
    assert "FLAG{" in res35["output"]

    res36 = run_lab_solve_step("36", 1)
    assert res36["success"] is True
    assert "Second-Order SQLi" in res36["name"]
    assert "FLAG{" in res36["output"]

    res37 = run_lab_solve_step("37", 1)
    assert res37["success"] is True
    assert "BLE" in res37["name"]
    assert "FLAG{" in res37["output"]

def test_invalid_lab_solver():
    """Test invalid lab handling."""
    res = run_lab_solve_step("99", 1)
    assert res["success"] is False
