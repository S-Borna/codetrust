// Copyright (c) Said Borna. All rights reserved.
// Proprietary — see LICENSE for terms.
/**
 * Import and Dockerfile extraction utilities.
 * Parses source files to extract package names and Docker image references.
 */

import type { Language } from "./types";

/** Extract import names from source code based on language. */
export function extractImports(code: string, language: Language): string[] {
    switch (language) {
        case "python":
            return extractPythonImports(code);
        case "javascript":
        case "typescript":
            return extractJsImports(code);
        case "go":
            return extractGoImports(code);
        case "rust":
            return extractRustImports(code);
        case "sql":
        case "yaml":
        case "shell":
        case "html":
        case "terraform":
            return [];
        case "java":
            return extractJavaImports(code);
        case "csharp":
            return extractCsharpImports(code);
        case "cpp":
            return extractCppIncludes(code);
        case "ruby":
            return extractRubyImports(code);
        case "php":
            return extractPhpImports(code);
        case "powershell":
            return [];
        default: {
            const _exhaustive: never = language;
            return [];
        }
    }
}

/** Extract Python import names (top-level packages only). */
function extractPythonImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();

        // import foo, import foo.bar
        const importMatch = trimmed.match(/^import\s+(\w+)/);
        if (importMatch) {
            imports.add(importMatch[1]);
        }

        // from foo import bar, from foo.bar import baz
        const fromMatch = trimmed.match(/^from\s+(\w+)/);
        if (fromMatch) {
            imports.add(fromMatch[1]);
        }
    }

    // Remove stdlib modules
    const stdlib = new Set([
        "os", "sys", "re", "math", "json", "time", "datetime", "collections",
        "itertools", "functools", "pathlib", "typing", "abc", "io", "copy",
        "enum", "dataclasses", "contextlib", "logging", "unittest", "hashlib",
        "secrets", "uuid", "base64", "hmac", "textwrap", "string", "struct",
        "csv", "configparser", "argparse", "subprocess", "shutil", "glob",
        "tempfile", "socket", "http", "urllib", "email", "html", "xml",
        "asyncio", "concurrent", "multiprocessing", "threading", "queue",
        "sqlite3", "zlib", "gzip", "zipfile", "tarfile", "pickle", "shelve",
        "marshal", "warnings", "traceback", "inspect", "dis", "ast",
        "importlib", "pkgutil", "pdb", "profile", "cProfile", "timeit",
        "random", "statistics", "decimal", "fractions", "operator",
        "pprint", "array", "heapq", "bisect", "weakref", "types",
        "codecs", "locale", "gettext", "platform", "sysconfig",
        "builtins", "__future__", "signal", "mmap", "ctypes", "select",
        "ssl", "ftplib", "smtplib", "xmlrpc", "ipaddress", "netrc",
    ]);

    return [...imports].filter((name) => !stdlib.has(name));
}

/** Extract JavaScript/TypeScript import package names. */
function extractJsImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();

        // import ... from "package"
        const esmMatch = trimmed.match(
            /^import\s+.*?\s+from\s+['"]([^./][^'"]*)['"]/,
        );
        if (esmMatch) {
            imports.add(extractNpmPackageName(esmMatch[1]));
        }

        // const x = require("package")
        const cjsMatch = trimmed.match(
            /require\s*\(\s*['"]([^./][^'"]*)['"]\s*\)/,
        );
        if (cjsMatch) {
            imports.add(extractNpmPackageName(cjsMatch[1]));
        }

        // Dynamic import("package")
        const dynMatch = trimmed.match(
            /import\s*\(\s*['"]([^./][^'"]*)['"]\s*\)/,
        );
        if (dynMatch) {
            imports.add(extractNpmPackageName(dynMatch[1]));
        }
    }

    // Remove Node built-ins
    const builtins = new Set([
        "fs", "path", "os", "http", "https", "url", "util", "events",
        "stream", "buffer", "crypto", "zlib", "net", "dns", "tls",
        "child_process", "cluster", "dgram", "readline", "repl",
        "vm", "assert", "querystring", "string_decoder", "timers",
        "tty", "v8", "worker_threads", "perf_hooks", "async_hooks",
        "node:fs", "node:path", "node:os", "node:http", "node:https",
        "node:url", "node:util", "node:events", "node:stream",
        "node:buffer", "node:crypto", "node:zlib", "node:net",
    ]);

    return [...imports].filter((name) => !builtins.has(name));
}

/** Extract the npm package name (handle scoped packages). */
function extractNpmPackageName(specifier: string): string {
    if (specifier.startsWith("@")) {
        const parts = specifier.split("/");
        if (parts.length >= 2) {
            return `${parts[0]}/${parts[1]}`;
        }
        return specifier;
    }
    return specifier.split("/")[0];
}

/** Extract Go import paths. */
function extractGoImports(code: string): string[] {
    const imports: string[] = [];

    // Single import: import "package"
    const singleMatches = code.matchAll(/import\s+"([^"]+)"/g);
    for (const match of singleMatches) {
        if (match[1] && !isGoStdlib(match[1])) {
            imports.push(match[1]);
        }
    }

    // Grouped import block
    const groupMatches = code.matchAll(
        /import\s*\(\s*([\s\S]*?)\s*\)/g,
    );
    for (const group of groupMatches) {
        if (!group[1]) {
            continue;
        }
        const lineMatches = group[1].matchAll(/"([^"]+)"/g);
        for (const m of lineMatches) {
            if (m[1] && !isGoStdlib(m[1])) {
                imports.push(m[1]);
            }
        }
    }

    return imports;
}

/** Check if a Go import is a standard library package. */
function isGoStdlib(pkg: string): boolean {
    return !pkg.includes(".");
}

/** Extract Rust crate names from use/extern crate statements. */
function extractRustImports(code: string): string[] {
    const crates = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();

        // extern crate foo;
        const externMatch = trimmed.match(/^extern\s+crate\s+(\w+)/);
        if (externMatch) {
            crates.add(externMatch[1]);
        }

        // use foo::bar;
        const useMatch = trimmed.match(/^use\s+(\w+)::/);
        if (useMatch) {
            crates.add(useMatch[1]);
        }
    }

    // Remove std/core crates
    const stdCrates = new Set([
        "std", "core", "alloc", "proc_macro", "test",
    ]);

    return [...crates].filter((name) => !stdCrates.has(name));
}

/** Extract Java import package names (third-party only). */
function extractJavaImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();
        // import com.google.gson.Gson; -> "com.google.gson"
        // import static org.junit.Assert.*; -> "org.junit"
        const match = trimmed.match(/^import\s+(static\s+){0,1}(\w+(\.\w+)*)\.\w+;/);
        if (match) {
            const pkg = match[2];
            // Skip java/javax standard library
            if (!pkg.startsWith("java.") && !pkg.startsWith("javax.") && !pkg.startsWith("sun.")) {
                // Use group ID (first 2-3 segments): com.google.gson -> com.google.gson
                imports.add(pkg);
            }
        }
    }

    return [...imports];
}

/** Extract C# using directives (third-party namespaces). */
function extractCsharpImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    const stdNamespaces = new Set([
        "System", "Microsoft", "Windows",
    ]);

    for (const line of lines) {
        const trimmed = line.trim();
        // using Newtonsoft.Json;
        // using static Newtonsoft.Json.JsonConvert;
        const match = trimmed.match(/^using\s+(static\s+){0,1}(\w+(\.\w+)*)\s*;/);
        if (match) {
            const ns = match[2];
            const topLevel = ns.split(".")[0];
            if (!stdNamespaces.has(topLevel)) {
                imports.add(ns);
            }
        }
    }

    return [...imports];
}

/** Extract C/C++ include directives (non-standard headers). */
function extractCppIncludes(code: string): string[] {
    const includes = new Set<string>();
    const lines = code.split("\n");

    const stdHeaders = new Set([
        "iostream", "string", "vector", "map", "set", "algorithm", "cstdio",
        "cstring", "cstdlib", "cmath", "cassert", "ctime", "climits",
        "cfloat", "fstream", "sstream", "iomanip", "memory", "functional",
        "numeric", "iterator", "utility", "tuple", "array", "deque",
        "list", "queue", "stack", "bitset", "complex", "valarray",
        "regex", "atomic", "thread", "mutex", "condition_variable",
        "chrono", "random", "ratio", "type_traits", "typeinfo",
        "stdexcept", "exception", "new", "limits", "locale",
        "initializer_list", "optional", "variant", "any", "filesystem",
        "span", "ranges", "concepts", "coroutine", "format",
        "stdio.h", "stdlib.h", "string.h", "math.h", "assert.h",
        "ctype.h", "errno.h", "float.h", "limits.h", "locale.h",
        "signal.h", "stdarg.h", "stddef.h", "time.h", "unistd.h",
        "pthread.h", "sys/types.h", "sys/stat.h", "fcntl.h",
    ]);

    for (const line of lines) {
        const trimmed = line.trim();
        // #include <boost/asio.hpp> or #include "mylib.h"
        const match = trimmed.match(/^#\s*include\s+[<"]([^>"]+)[>"]/);
        if (match) {
            const header = match[1];
            if (!stdHeaders.has(header) && !header.startsWith("sys/")) {
                includes.add(header);
            }
        }
    }

    return [...includes];
}

/** Extract Ruby require names (top-level gems only). */
function extractRubyImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();
        // require "foo" / require 'foo'
        const requireMatch = trimmed.match(/^require\s+['"]([^'"]+)['"]/);
        if (requireMatch) {
            const name = requireMatch[1].split("/")[0];
            imports.add(name);
        }
    }

    return [...imports];
}

/** Extract PHP use/require names (top-level packages only). */
function extractPhpImports(code: string): string[] {
    const imports = new Set<string>();
    const lines = code.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();
        // use Vendor\Package\Class;
        const useMatch = trimmed.match(/^use\s+([A-Z]\w+(?:\\[A-Z]\w+)*)/);
        if (useMatch) {
            const ns = useMatch[1].split("\\")[0];
            imports.add(ns);
        }
    }

    return [...imports];
}

/** Docker image reference parsed from a Dockerfile. */
export interface DockerImage {
    image: string;
    tag: string;
}

/** Extract Docker image references from Dockerfile content. */
export function extractDockerImages(content: string): DockerImage[] {
    const images: DockerImage[] = [];
    const lines = content.split("\n");

    for (const line of lines) {
        const trimmed = line.trim();

        // FROM image:tag [AS name]
        const fromMatch = trimmed.match(
            /^FROM\s+(--platform=\S+\s+){0,1}([^\s:]+)(:(\S+)){0,1}(\s+AS\s+\S+){0,1}$/i,
        );
        if (!fromMatch) {
            continue;
        }

        const imageName = fromMatch[2];
        const tag = fromMatch[4] || "latest";

        // Skip scratch and build stage references ($variable)
        if (imageName === "scratch" || imageName.startsWith("$")) {
            continue;
        }

        images.push({ image: imageName, tag });
    }

    return images;
}
