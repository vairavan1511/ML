"""In-memory storage for analysis results used by report downloads."""
from __future__ import annotations

from copy import deepcopy
from uuid import uuid4

_CASES: dict[str, dict] = {}


def save(result: dict) -> str:
    case_id = uuid4().hex
    _CASES[case_id] = deepcopy(result)
    return case_id


def get(case_id: str) -> dict | None:
    result = _CASES.get(case_id)
    return deepcopy(result) if result is not None else None
