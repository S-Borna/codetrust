/**
 * Unit tests for the CodeTrust type definitions and language mapping.
 */

import * as assert from "assert";
import { LANGUAGE_MAP, DOCKERFILE_LANGUAGE_IDS } from "../../types";

suite("Types Tests", () => {
  suite("LANGUAGE_MAP", () => {
    test("maps python", () => {
      assert.strictEqual(LANGUAGE_MAP["python"], "python");
    });

    test("maps javascript", () => {
      assert.strictEqual(LANGUAGE_MAP["javascript"], "javascript");
    });

    test("maps typescript", () => {
      assert.strictEqual(LANGUAGE_MAP["typescript"], "typescript");
    });

    test("maps typescriptreact to typescript", () => {
      assert.strictEqual(LANGUAGE_MAP["typescriptreact"], "typescript");
    });

    test("maps javascriptreact to javascript", () => {
      assert.strictEqual(LANGUAGE_MAP["javascriptreact"], "javascript");
    });

    test("maps go", () => {
      assert.strictEqual(LANGUAGE_MAP["go"], "go");
    });

    test("maps rust", () => {
      assert.strictEqual(LANGUAGE_MAP["rust"], "rust");
    });

    test("returns undefined for unknown languages", () => {
      assert.strictEqual(LANGUAGE_MAP["java"], undefined);
      assert.strictEqual(LANGUAGE_MAP["cpp"], undefined);
    });
  });

  suite("DOCKERFILE_LANGUAGE_IDS", () => {
    test("includes dockerfile", () => {
      assert.ok(DOCKERFILE_LANGUAGE_IDS.has("dockerfile"));
    });

    test("does not include python", () => {
      assert.ok(!DOCKERFILE_LANGUAGE_IDS.has("python"));
    });
  });
});
