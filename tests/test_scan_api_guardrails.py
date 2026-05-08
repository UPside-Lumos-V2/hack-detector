"""Static guardrails for scan API dependency creep."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


FORBIDDEN_SCAN_IDENTIFIERS = {
    "scan_api",
    "etherscan",
    "arbiscan",
    "basescan",
    "bscscan",
    "polygonscan",
}

TARGET_FILES = (
    Path(__file__).resolve().parents[1] / "src" / "scorer.py",
    Path(__file__).resolve().parents[1] / "src" / "alerter.py",
)


def _import_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0].lower())
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".", 1)[0].lower())
    return names


def _call_root_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id.lower()
    if isinstance(node, ast.Attribute):
        return _call_root_name(node.value)
    return None


def _call_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            root = _call_root_name(node.func)
            if root:
                names.add(root)
    return names


class ScanApiGuardrailTest(unittest.TestCase):
    def test_scorer_and_alerter_do_not_import_scan_clients(self) -> None:
        for path in TARGET_FILES:
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text())
                imports = _import_names(tree)
                self.assertTrue(FORBIDDEN_SCAN_IDENTIFIERS.isdisjoint(imports))

    def test_scorer_and_alerter_do_not_call_scan_clients(self) -> None:
        for path in TARGET_FILES:
            with self.subTest(path=path.name):
                tree = ast.parse(path.read_text())
                calls = _call_names(tree)
                self.assertTrue(FORBIDDEN_SCAN_IDENTIFIERS.isdisjoint(calls))


if __name__ == "__main__":
    _ = unittest.main()
