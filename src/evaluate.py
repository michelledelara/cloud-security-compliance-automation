from __future__ import annotations

from typing import Any, Dict, List
from .checks import CHECKS

def evaluate(inventory: Dict[str, Any], control_library: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for control in control_library.get("controls", []):
        check = CHECKS.get(control["id"])
        if check:
            findings.extend(check(inventory, control))
    return findings
