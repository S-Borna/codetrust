# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for data classification CLI commands."""

from __future__ import annotations

import argparse
import json

from src.cli import cmd_classify


class TestClassifyFile:
    """Test file classification via CLI."""

    def test_classify_readme(self) -> None:
        args = argparse.Namespace(
            path="README.md", stdin=False, model="",
            report=False, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 0

    def test_classify_with_model(self) -> None:
        args = argparse.Namespace(
            path="README.md", stdin=False, model="gpt-4o",
            report=False, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 0

    def test_classify_json_output(self) -> None:
        args = argparse.Namespace(
            path="README.md", stdin=False, model="",
            report=False, json_output=True,
        )
        result = cmd_classify(args)
        assert result == 0


class TestClassifyDirectory:
    """Test directory classification."""

    def test_classify_src_dir(self) -> None:
        args = argparse.Namespace(
            path="src/services", stdin=False, model="",
            report=True, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 0

    def test_classify_dir_with_model(self) -> None:
        args = argparse.Namespace(
            path="src/services", stdin=False, model="gpt-4o",
            report=True, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 0


class TestClassifyEdgeCases:
    """Test edge cases."""

    def test_nonexistent_path_returns_error(self) -> None:
        args = argparse.Namespace(
            path="/nonexistent/file.py", stdin=False, model="",
            report=False, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 1

    def test_no_args_returns_usage(self) -> None:
        args = argparse.Namespace(
            path="", stdin=False, model="",
            report=False, json_output=False,
        )
        result = cmd_classify(args)
        assert result == 1
