"""Tests for parsers module — import extraction, requirements, Dockerfile parsing."""


from src.utils.parsers import (
    extract_go_imports,
    extract_js_imports,
    extract_python_imports,
    extract_rust_imports,
    parse_cargo_toml,
    parse_dockerfile_from,
    parse_go_mod,
    parse_package_json_deps,
    parse_requirements_txt,
)

# --- Python import extraction ---


def test_extract_python_imports_basic() -> None:
    """Extract simple import statements."""
    code = "import requests\nimport flask\n"
    result = extract_python_imports(code)
    assert "requests" in result
    assert "flask" in result


def test_extract_python_imports_from() -> None:
    """Extract from...import statements."""
    code = "from fastapi import FastAPI\nfrom pydantic import BaseModel\n"
    result = extract_python_imports(code)
    assert "fastapi" in result
    assert "pydantic" in result


def test_extract_python_imports_skips_stdlib() -> None:
    """Standard library modules should not appear."""
    code = "import os\nimport sys\nimport json\nimport requests\n"
    result = extract_python_imports(code)
    assert "os" not in result
    assert "sys" not in result
    assert "json" not in result
    assert "requests" in result


def test_extract_python_imports_empty() -> None:
    """Empty code returns empty list."""
    result = extract_python_imports("")
    assert result == []


def test_extract_python_imports_comments_ignored() -> None:
    """Commented imports should be skipped."""
    code = "# import evil_package\nimport requests\n"
    result = extract_python_imports(code)
    assert "evil_package" not in result
    assert "requests" in result


# --- JavaScript import extraction ---


def test_extract_js_imports_require() -> None:
    """Extract CommonJS require() statements."""
    code = 'const express = require("express");\nconst _ = require("lodash");\n'
    result = extract_js_imports(code)
    assert "express" in result
    assert "lodash" in result


def test_extract_js_imports_esm() -> None:
    """Extract ES module import statements."""
    code = 'import React from "react";\nimport { useState } from "react";\n'
    result = extract_js_imports(code)
    assert "react" in result


def test_extract_js_imports_skips_relative() -> None:
    """Relative imports should be excluded."""
    code = 'import foo from "./foo";\nimport bar from "../bar";\nimport axios from "axios";\n'
    result = extract_js_imports(code)
    assert "axios" in result
    # Relative paths should not appear
    for r in result:
        assert not r.startswith(".")


def test_extract_js_imports_empty() -> None:
    """Empty code returns empty list."""
    result = extract_js_imports("")
    assert result == []


# --- Go import extraction ---


def test_extract_go_imports_single() -> None:
    """Extract single Go import."""
    code = 'import "github.com/gin-gonic/gin"\n'
    result = extract_go_imports(code)
    assert "github.com/gin-gonic/gin" in result


def test_extract_go_imports_block() -> None:
    """Extract Go import block."""
    code = 'import (\n\t"fmt"\n\t"github.com/gin-gonic/gin"\n)\n'
    result = extract_go_imports(code)
    assert "github.com/gin-gonic/gin" in result


def test_extract_go_imports_skips_stdlib() -> None:
    """Standard library imports should be filtered out."""
    code = 'import (\n\t"fmt"\n\t"net/http"\n\t"github.com/gin-gonic/gin"\n)\n'
    result = extract_go_imports(code)
    assert "fmt" not in result
    assert "github.com/gin-gonic/gin" in result


def test_extract_go_imports_empty() -> None:
    """Empty code returns empty list."""
    result = extract_go_imports("")
    assert result == []


# --- Rust import extraction ---


def test_extract_rust_imports_extern_crate() -> None:
    """Extract extern crate declarations."""
    code = "extern crate serde;\nextern crate tokio;\n"
    result = extract_rust_imports(code)
    assert "serde" in result
    assert "tokio" in result


def test_extract_rust_imports_use() -> None:
    """Extract use statements for external crates."""
    code = "use serde::Deserialize;\nuse tokio::runtime;\n"
    result = extract_rust_imports(code)
    assert "serde" in result
    assert "tokio" in result


def test_extract_rust_imports_empty() -> None:
    """Empty code returns empty list."""
    result = extract_rust_imports("")
    assert result == []


# --- requirements.txt parsing ---


def test_parse_requirements_basic() -> None:
    """Parse simple pinned requirements."""
    content = "requests==2.31.0\nflask>=2.0\n"
    result = parse_requirements_txt(content)
    assert "requests" in result
    assert result["requests"] == "2.31.0"


def test_parse_requirements_comments() -> None:
    """Comments and blank lines are skipped."""
    content = "# comment\n\nrequests==2.31.0\n"
    result = parse_requirements_txt(content)
    assert "requests" in result


def test_parse_requirements_empty() -> None:
    """Empty content returns empty dict."""
    result = parse_requirements_txt("")
    assert result == {}


# --- package.json parsing ---


def test_parse_package_json_deps() -> None:
    """Parse dependencies from package.json content."""
    content = '{"dependencies": {"express": "^4.18.0", "lodash": "4.17.21"}}'
    result = parse_package_json_deps(content)
    assert "express" in result
    assert "lodash" in result


def test_parse_package_json_invalid() -> None:
    """Invalid JSON returns empty dict."""
    result = parse_package_json_deps("not json")
    assert result == {}


# --- Dockerfile FROM parsing ---


def test_parse_dockerfile_from_basic() -> None:
    """Parse basic FROM statement."""
    content = "FROM python:3.12-slim\n"
    result = parse_dockerfile_from(content)
    assert len(result) >= 1
    assert result[0] == ("python", "3.12-slim")


def test_parse_dockerfile_from_no_tag() -> None:
    """FROM without tag defaults to 'latest'."""
    content = "FROM nginx\n"
    result = parse_dockerfile_from(content)
    assert len(result) >= 1
    assert result[0][1] == "latest"


def test_parse_dockerfile_from_multiple() -> None:
    """Parse multi-stage Dockerfile."""
    content = "FROM node:18-alpine AS builder\nFROM nginx:1.25\n"
    result = parse_dockerfile_from(content)
    assert len(result) == 2


def test_parse_dockerfile_from_empty() -> None:
    """Empty content returns empty list."""
    result = parse_dockerfile_from("")
    assert result == []


# --- go.mod parsing ---


def test_parse_go_mod() -> None:
    """Parse go.mod require statements."""
    content = """module example.com/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4
)
"""
    result = parse_go_mod(content)
    assert "github.com/gin-gonic/gin" in result


def test_parse_go_mod_empty() -> None:
    """Empty go.mod returns empty dict."""
    result = parse_go_mod("")
    assert result == {}


# --- Cargo.toml parsing ---


def test_parse_cargo_toml() -> None:
    """Parse Cargo.toml dependencies."""
    content = """[dependencies]
serde = "1.0"
tokio = { version = "1", features = ["full"] }
"""
    result = parse_cargo_toml(content)
    assert "serde" in result


def test_parse_cargo_toml_empty() -> None:
    """Empty Cargo.toml returns empty dict."""
    result = parse_cargo_toml("")
    assert result == {}
