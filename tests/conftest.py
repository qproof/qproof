"""Shared fixtures for qproof tests."""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_project() -> Path:
    """Path to the sample project fixture."""
    return FIXTURES_DIR / "sample_project"


@pytest.fixture
def empty_project() -> Path:
    """Path to the empty project fixture."""
    return FIXTURES_DIR / "empty_project"
