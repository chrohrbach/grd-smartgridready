"""The documentation must not drift from the code it describes."""

from __future__ import annotations

import re

from conftest import ROOT

from grd_sgr import runner
from grd_sgr.framework import REGISTRY
from grd_sgr.tests_dynamic import HOLD_BACK_RESULTS, NO_ACTION_RESULTS, OUTCOME_RESULTS


def test_every_registered_test_is_in_the_catalogue():
    catalogue = (ROOT / "docs" / "TEST_CATALOGUE.md").read_text(encoding="utf-8")
    rows = set(re.findall(r"^\| ([A-Z]\d) ", catalogue, flags=re.M))
    assert rows == set(REGISTRY)


def test_catalogue_states_the_run_order():
    catalogue = (ROOT / "docs" / "TEST_CATALOGUE.md").read_text(encoding="utf-8")
    assert ", ".join(runner.DYNAMIC_ORDER) in catalogue


def test_evidence_contract_lists_every_decision_result_the_bench_reads():
    contract = (ROOT / "docs" / "EVIDENCE_API.md").read_text(encoding="utf-8")
    for result in OUTCOME_RESULTS | HOLD_BACK_RESULTS | NO_ACTION_RESULTS:
        assert f"`{result}`" in contract, result
