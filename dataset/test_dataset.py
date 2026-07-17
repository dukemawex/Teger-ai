"""Tests for the open phishing-pattern dataset. Run: python -m pytest dataset/"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from schema import load_patterns, validate_all
from taxonomy import TACTICS, is_valid_tactic


def test_dataset_is_valid():
    n, errors = validate_all()
    assert n > 0
    assert errors == [], f"dataset errors: {errors}"


def test_ids_are_unique():
    ids = [p.id for p in load_patterns()]
    assert len(ids) == len(set(ids))


def test_every_tactic_slug_is_known():
    for p in load_patterns():
        assert is_valid_tactic(p.tactic), f"{p.id} has unknown tactic {p.tactic}"


def test_covers_multiple_tactics():
    used = {p.tactic for p in load_patterns()}
    assert len(used) >= 6, "seed should demonstrate breadth across the taxonomy"


def test_prompt_injection_family_present():
    # the agentic/context-injection tactic ties this repo to the reasoning-monitor line
    assert any(p.tactic == "context_injection" for p in load_patterns())
