/**
 * Unit tests for the import/Dockerfile parser utilities.
 * These tests run without VS Code API dependencies.
 */

import * as assert from "assert";
import { extractImports, extractDockerImages } from "../../parsers";

suite("Parser Tests", () => {
  suite("extractImports — Python", () => {
    test("extracts simple imports", () => {
      const code = `import requests\nimport flask\n`;
      const result = extractImports(code, "python");
      assert.deepStrictEqual(result, ["requests", "flask"]);
    });

    test("extracts from-imports", () => {
      const code = `from fastapi import FastAPI\nfrom pydantic import BaseModel\n`;
      const result = extractImports(code, "python");
      assert.deepStrictEqual(result, ["fastapi", "pydantic"]);
    });

    test("filters stdlib modules", () => {
      const code = `import os\nimport sys\nimport json\nimport requests\n`;
      const result = extractImports(code, "python");
      assert.deepStrictEqual(result, ["requests"]);
    });

    test("handles mixed imports", () => {
      const code = `import os\nfrom flask import Flask\nimport numpy\nfrom pathlib import Path\n`;
      const result = extractImports(code, "python");
      assert.ok(result.includes("flask"));
      assert.ok(result.includes("numpy"));
      assert.ok(!result.includes("os"));
      assert.ok(!result.includes("pathlib"));
    });

    test("returns empty for stdlib-only code", () => {
      const code = `import os\nimport sys\nimport json\n`;
      const result = extractImports(code, "python");
      assert.deepStrictEqual(result, []);
    });
  });

  suite("extractImports — JavaScript", () => {
    test("extracts ESM imports", () => {
      const code = `import React from "react";\nimport { useState } from "react";\n`;
      const result = extractImports(code, "javascript");
      assert.deepStrictEqual(result, ["react"]);
    });

    test("extracts CJS requires", () => {
      const code = `const express = require("express");\nconst path = require("path");\n`;
      const result = extractImports(code, "javascript");
      assert.deepStrictEqual(result, ["express"]);
    });

    test("extracts scoped packages", () => {
      const code = `import { test } from "@jest/globals";\n`;
      const result = extractImports(code, "javascript");
      assert.deepStrictEqual(result, ["@jest/globals"]);
    });

    test("filters Node builtins", () => {
      const code = `import fs from "fs";\nimport path from "path";\nimport express from "express";\n`;
      const result = extractImports(code, "javascript");
      assert.deepStrictEqual(result, ["express"]);
    });
  });

  suite("extractImports — Go", () => {
    test("extracts single import", () => {
      const code = `import "github.com/gin-gonic/gin"\n`;
      const result = extractImports(code, "go");
      assert.deepStrictEqual(result, ["github.com/gin-gonic/gin"]);
    });

    test("extracts grouped imports", () => {
      const code = `import (\n  "fmt"\n  "github.com/go-chi/chi"\n  "net/http"\n)\n`;
      const result = extractImports(code, "go");
      assert.deepStrictEqual(result, ["github.com/go-chi/chi"]);
    });

    test("filters stdlib (no dots)", () => {
      const code = `import "fmt"\nimport "net/http"\n`;
      const result = extractImports(code, "go");
      assert.deepStrictEqual(result, []);
    });
  });

  suite("extractImports — Rust", () => {
    test("extracts use statements", () => {
      const code = `use serde::Serialize;\nuse tokio::runtime;\n`;
      const result = extractImports(code, "rust");
      assert.ok(result.includes("serde"));
      assert.ok(result.includes("tokio"));
    });

    test("extracts extern crate", () => {
      const code = `extern crate rand;\n`;
      const result = extractImports(code, "rust");
      assert.deepStrictEqual(result, ["rand"]);
    });

    test("filters std crates", () => {
      const code = `use std::collections::HashMap;\nuse serde_json::Value;\n`;
      const result = extractImports(code, "rust");
      assert.deepStrictEqual(result, ["serde_json"]);
    });
  });

  suite("extractDockerImages", () => {
    test("extracts simple FROM", () => {
      const content = `FROM python:3.12-slim\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, [
        { image: "python", tag: "3.12-slim" },
      ]);
    });

    test("defaults tag to latest", () => {
      const content = `FROM nginx\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, [
        { image: "nginx", tag: "latest" },
      ]);
    });

    test("handles multi-stage FROM", () => {
      const content = `FROM node:20 AS builder\nFROM nginx:alpine\n`;
      const result = extractDockerImages(content);
      assert.strictEqual(result.length, 2);
      assert.deepStrictEqual(result[0], { image: "node", tag: "20" });
      assert.deepStrictEqual(result[1], { image: "nginx", tag: "alpine" });
    });

    test("skips scratch", () => {
      const content = `FROM scratch\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, []);
    });

    test("skips variable references", () => {
      const content = `FROM $BASE_IMAGE:latest\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, []);
    });

    test("handles platform flag", () => {
      const content = `FROM --platform=linux/amd64 python:3.12\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, [
        { image: "python", tag: "3.12" },
      ]);
    });

    test("handles registry-prefixed images", () => {
      const content = `FROM ghcr.io/owner/image:v1.0\n`;
      const result = extractDockerImages(content);
      assert.deepStrictEqual(result, [
        { image: "ghcr.io/owner/image", tag: "v1.0" },
      ]);
    });
  });
});
