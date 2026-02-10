"""Fuzzy matching for package name suggestions using difflib."""

from difflib import get_close_matches

# Top popular PyPI packages for fuzzy matching suggestions
TOP_PYPI_PACKAGES: list[str] = [
    "requests", "boto3", "urllib3", "setuptools", "typing-extensions", "botocore",
    "certifi", "charset-normalizer", "idna", "pip", "python-dateutil", "s3transfer",
    "numpy", "packaging", "pyyaml", "six", "cryptography", "jmespath", "cffi",
    "wheel", "pycparser", "pyasn1", "attrs", "click", "importlib-metadata",
    "platformdirs", "zipp", "tomli", "pytz", "markupsafe", "jinja2", "colorama",
    "pillow", "pydantic", "filelock", "aiohttp", "protobuf", "grpcio", "pytest",
    "decorator", "wrapt", "pygments", "pluggy", "scipy", "pyjwt", "pandas",
    "soupsieve", "beautifulsoup4", "jsonschema", "frozenlist", "multidict",
    "aiosignal", "yarl", "google-api-core", "regex", "fsspec", "openpyxl",
    "pyarrow", "tqdm", "google-auth", "rsa", "cachetools", "exceptiongroup",
    "isodate", "async-timeout", "distlib", "iniconfig", "google-cloud-storage",
    "psutil", "lxml", "pydantic-core", "docutils", "pyparsing", "virtualenv",
    "annotated-types", "pyasn1-modules", "google-resumable-media", "sqlalchemy",
    "google-api-python-client", "google-cloud-core", "oauthlib", "grpcio-status",
    "proto-plus", "requests-oauthlib", "httplib2", "googleapis-common-protos",
    "tomlkit", "flask", "werkzeug", "itsdangerous", "ruamel-yaml", "tzdata",
    "greenlet", "scikit-learn", "httpx", "httpcore", "sniffio", "anyio", "h11",
    "tabulate", "msal", "portalocker", "rich", "markdown-it-py", "mdurl",
    "azure-core", "azure-storage-blob", "azure-identity", "msal-extensions",
    "msgpack", "ujson", "orjson", "simplejson", "xmltodict", "toml",
    "python-dotenv", "python-magic", "python-multipart", "python-jose",
    "paramiko", "fabric", "invoke", "celery", "kombu", "billiard", "amqp",
    "redis", "pymongo", "motor", "psycopg2", "psycopg2-binary", "mysqlclient",
    "sqlmodel", "alembic", "mako", "fastapi", "uvicorn", "starlette", "gunicorn",
    "django", "djangorestframework", "django-cors-headers", "django-filter",
    "tornado", "aiofiles", "websockets", "sanic", "falcon", "bottle", "cherrypy",
    "black", "isort", "flake8", "mypy", "pylint", "autopep8", "yapf", "ruff",
    "pre-commit", "bandit", "safety", "coverage", "pytest-cov", "pytest-asyncio",
    "pytest-mock", "pytest-xdist", "hypothesis", "faker", "factory-boy", "tox",
    "nox", "sphinx", "mkdocs", "pdoc", "twine", "build", "hatchling", "flit",
    "poetry", "setuptools-scm", "bump2version", "semantic-version",
    "tensorflow", "torch", "keras", "scikit-image", "opencv-python", "matplotlib",
    "seaborn", "plotly", "bokeh", "dash", "streamlit", "gradio", "transformers",
    "datasets", "tokenizers", "accelerate", "diffusers", "langchain", "openai",
    "anthropic", "cohere", "tiktoken", "sentence-transformers", "faiss-cpu",
    "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "boto3-stubs", "types-requests", "types-pyyaml", "types-redis",
    "arrow", "pendulum", "babel", "pyicu", "phonenumbers",
    "pynacl", "bcrypt", "passlib", "argon2-cffi", "itsdangerous",
    "structlog", "loguru", "sentry-sdk", "datadog", "prometheus-client",
    "docker", "kubernetes", "ansible", "salt", "pulumi",
    "typer", "fire", "plac", "docopt", "argparse",
    "httpie", "pygithub", "gitpython", "dulwich",
    "pydantic-settings", "dynaconf", "decouple", "environs",
    "marshmallow", "cattrs", "dacite", "dataclasses-json",
    "aioredis", "aiomysql", "aiopg", "asyncpg", "databases",
    "tenacity", "backoff", "retry", "stamina",
    "apscheduler", "schedule", "rq", "dramatiq", "huey",
    "pillow", "wand", "cairosvg", "svgwrite",
    "networkx", "igraph", "graph-tool",
    "sympy", "mpmath", "gmpy2",
    "cryptography", "pyopenssl", "certifi", "truststore",
    "mcp", "sse-starlette", "pydantic-ai",
]

# Top popular npm packages for fuzzy matching suggestions
TOP_NPM_PACKAGES: list[str] = [
    "lodash", "react", "chalk", "express", "debug", "commander", "tslib",
    "react-dom", "glob", "minimatch", "supports-color", "async", "uuid",
    "fs-extra", "axios", "bluebird", "moment", "inquirer", "mkdirp",
    "underscore", "typescript", "yargs", "webpack", "rimraf", "semver",
    "prop-types", "body-parser", "classnames", "ws", "dotenv", "request",
    "colors", "rxjs", "core-js", "through2", "jquery", "acorn", "cheerio",
    "yargs-parser", "chokidar", "minimist", "postcss", "source-map",
    "escape-string-regexp", "ms", "resolve", "ansi-styles", "eslint",
    "path-exists", "readable-stream", "p-locate", "cross-spawn", "execa",
    "graceful-fs", "locate-path", "strip-ansi", "p-limit", "find-up",
    "babel-runtime", "string-width", "wrappy", "once", "path-is-absolute",
    "has-flag", "safe-buffer", "is-fullwidth-code-point", "cliui", "wrap-ansi",
    "kind-of", "color-convert", "color-name", "concat-map", "brace-expansion",
    "inherits", "isarray", "ansi-regex", "path-type", "esprima",
    "next", "vue", "angular", "svelte", "nuxt", "gatsby", "remix",
    "prisma", "@prisma/client", "mongoose", "sequelize", "typeorm", "knex",
    "jest", "mocha", "vitest", "cypress", "playwright", "@testing-library/react",
    "prettier", "eslint-plugin-react", "eslint-config-prettier",
    "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
    "@emotion/react", "@emotion/styled", "material-ui", "@mui/material",
    "zod", "yup", "joi", "ajv", "class-validator",
    "@types/node", "@types/react", "@types/express", "@types/jest",
    "socket.io", "socket.io-client", "mqtt", "amqplib",
    "cors", "helmet", "morgan", "compression", "cookie-parser",
    "passport", "jsonwebtoken", "bcrypt", "bcryptjs",
    "redis", "ioredis", "bull", "bullmq",
    "winston", "pino", "bunyan", "morgan",
    "nodemailer", "sendgrid", "@sendgrid/mail",
    "sharp", "jimp", "canvas",
    "d3", "chart.js", "recharts", "victory", "nivo",
    "three", "babylon", "pixi.js", "phaser",
    "firebase", "firebase-admin", "supabase", "@supabase/supabase-js",
    "aws-sdk", "@aws-sdk/client-s3", "googleapis", "@google-cloud/storage",
    "openai", "langchain", "@anthropic-ai/sdk",
    "graphql", "apollo-server", "@apollo/client", "urql",
    "trpc", "@trpc/server", "@trpc/client", "@trpc/react-query",
    "swr", "react-query", "@tanstack/react-query",
    "zustand", "jotai", "recoil", "valtio", "mobx", "redux", "@reduxjs/toolkit",
    "framer-motion", "react-spring", "gsap", "animejs",
    "i18next", "react-i18next", "intl-messageformat",
    "date-fns", "dayjs", "luxon", "moment-timezone",
    "nanoid", "cuid", "ulid",
    "p-queue", "p-map", "p-all", "p-retry",
    "cli-progress", "ora", "listr2", "ink",
    "esbuild", "rollup", "parcel", "turbopack", "swc",
    "nodemon", "ts-node", "tsx", "concurrently", "npm-run-all",
]


def suggest_similar_package(
    package: str,
    known_packages: list[str] | None = None,
    cutoff: float = 0.6,
    max_results: int = 3,
) -> str:
    """Find similar package names using fuzzy matching.

    Args:
        package: The unknown package name to match.
        known_packages: List to match against (defaults to combined PyPI + npm).
        cutoff: Minimum similarity ratio (0.0-1.0).
        max_results: Maximum number of suggestions.

    Returns:
        Suggestion string like "Did you mean: requests, request?" or empty.
    """
    if known_packages is None:
        known_packages = TOP_PYPI_PACKAGES + TOP_NPM_PACKAGES

    matches = get_close_matches(
        package.lower(),
        [p.lower() for p in known_packages],
        n=max_results,
        cutoff=cutoff,
    )

    if not matches:
        return ""

    # Map back to original casing
    lower_to_original = {p.lower(): p for p in known_packages}
    suggestions = [lower_to_original.get(m, m) for m in matches]

    return f"Did you mean: {', '.join(suggestions)}?"


def suggest_pypi_package(package: str) -> str:
    """Suggest similar PyPI package names."""
    return suggest_similar_package(package, TOP_PYPI_PACKAGES)


def suggest_npm_package(package: str) -> str:
    """Suggest similar npm package names."""
    return suggest_similar_package(package, TOP_NPM_PACKAGES)
