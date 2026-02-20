# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
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

# Top popular crates.io packages for fuzzy matching suggestions
TOP_CRATES_PACKAGES: list[str] = [
    "serde", "serde_json", "tokio", "rand", "clap", "log", "regex", "anyhow",
    "thiserror", "chrono", "reqwest", "hyper", "actix-web", "axum", "warp",
    "tracing", "tracing-subscriber", "env_logger", "futures", "async-trait",
    "syn", "quote", "proc-macro2", "bytes", "http", "url", "uuid", "base64",
    "sha2", "hmac", "aes", "rsa", "ring", "rustls", "native-tls",
    "sqlx", "diesel", "rusqlite", "mongodb", "redis", "deadpool", "r2d2",
    "serde_yaml", "toml", "config", "dotenv", "once_cell", "lazy_static",
    "itertools", "rayon", "crossbeam", "parking_lot", "dashmap",
    "num", "num-traits", "num-bigint", "num-rational",
    "image", "imageproc", "png", "jpeg-decoder",
    "tui", "ratatui", "crossterm", "termion", "colored", "console",
    "structopt", "clap_derive", "dialoguer", "indicatif",
    "prost", "tonic", "tarpc", "capnp",
    "tower", "tower-http", "tower-layer",
    "tempfile", "walkdir", "glob", "notify",
    "semver", "cargo_metadata", "vergen",
    "criterion", "proptest", "quickcheck", "mockall", "wiremock",
    "rocket", "poem", "tide", "gotham",
    "tera", "askama", "handlebars", "minijinja",
    "lettre", "mail-send",
    "aws-sdk-s3", "aws-config", "rusoto_core",
    "k8s-openapi", "kube", "bollard",
    "nix", "libc", "winapi", "windows",
    "arrow", "datafusion", "polars", "ndarray",
    "nom", "pest", "lalrpop", "logos", "chumsky",
    "miette", "color-eyre", "eyre",
    "strum", "derive_more", "derive_builder", "typed-builder",
    "bitflags", "enumflags2",
    "smallvec", "tinyvec", "arrayvec", "bumpalo",
    "memmap2", "memchr", "aho-corasick",
    "flate2", "zstd", "lz4", "brotli", "snap",
    "csv", "parquet",
    "rustfmt-nightly", "clippy",
    "wasm-bindgen", "web-sys", "js-sys", "gloo",
    "egui", "iced", "druid", "gtk-rs", "slint",
    "bevy", "macroquad", "ggez", "fyrox",
    "embedded-hal", "cortex-m", "esp-idf-hal",
    "openssl", "boring", "rcgen",
]

# Top popular Go modules for fuzzy matching suggestions
TOP_GO_MODULES: list[str] = [
    "github.com/gin-gonic/gin",
    "github.com/gorilla/mux",
    "github.com/go-chi/chi",
    "github.com/labstack/echo",
    "github.com/gofiber/fiber",
    "github.com/stretchr/testify",
    "github.com/sirupsen/logrus",
    "go.uber.org/zap",
    "github.com/rs/zerolog",
    "github.com/spf13/cobra",
    "github.com/spf13/viper",
    "github.com/spf13/pflag",
    "github.com/urfave/cli",
    "google.golang.org/grpc",
    "google.golang.org/protobuf",
    "github.com/grpc-ecosystem/grpc-gateway",
    "github.com/go-playground/validator",
    "github.com/go-sql-driver/mysql",
    "github.com/lib/pq",
    "github.com/jackc/pgx",
    "github.com/jmoiron/sqlx",
    "gorm.io/gorm",
    "gorm.io/driver/postgres",
    "gorm.io/driver/mysql",
    "gorm.io/driver/sqlite",
    "github.com/redis/go-redis",
    "go.mongodb.org/mongo-driver",
    "github.com/aws/aws-sdk-go-v2",
    "cloud.google.com/go",
    "github.com/Azure/azure-sdk-for-go",
    "github.com/prometheus/client_golang",
    "go.opentelemetry.io/otel",
    "github.com/uber-go/fx",
    "github.com/google/wire",
    "github.com/golang-jwt/jwt",
    "golang.org/x/crypto",
    "golang.org/x/net",
    "golang.org/x/text",
    "golang.org/x/sync",
    "golang.org/x/time",
    "golang.org/x/oauth2",
    "golang.org/x/tools",
    "golang.org/x/sys",
    "golang.org/x/mod",
    "golang.org/x/exp",
    "github.com/google/uuid",
    "github.com/google/go-cmp",
    "github.com/pkg/errors",
    "github.com/hashicorp/consul",
    "github.com/hashicorp/vault",
    "github.com/hashicorp/terraform",
    "github.com/hashicorp/go-multierror",
    "github.com/hashicorp/go-retryablehttp",
    "github.com/mitchellh/mapstructure",
    "github.com/fatih/color",
    "github.com/olekukonern/tablewriter",
    "github.com/schollz/progressbar",
    "github.com/tidwall/gjson",
    "github.com/tidwall/sjson",
    "github.com/json-iterator/go",
    "github.com/mailru/easyjson",
    "github.com/valyala/fasthttp",
    "github.com/valyala/fastjson",
    "github.com/go-resty/resty",
    "github.com/parnurzeal/gorequest",
    "github.com/cenkalti/backoff",
    "github.com/avast/retry-go",
    "github.com/robfig/cron",
    "github.com/go-co-op/gocron",
    "github.com/nats-io/nats.go",
    "github.com/segmentio/kafka-go",
    "github.com/rabbitmq/amqp091-go",
    "github.com/gorilla/websocket",
    "github.com/coder/websocket",
    "github.com/docker/docker",
    "github.com/testcontainers/testcontainers-go",
    "github.com/stretchr/objx",
    "github.com/DATA-DOG/go-sqlmock",
    "github.com/jarcoal/httpmock",
    "github.com/golang/mock",
    "github.com/onsi/ginkgo",
    "github.com/onsi/gomega",
    "github.com/go-swagger/go-swagger",
    "github.com/swaggo/swag",
    "github.com/go-openapi/spec",
    "github.com/dgraph-io/badger",
    "github.com/etcd-io/bbolt",
    "github.com/syndtr/goleveldb",
    "github.com/elastic/go-elasticsearch",
    "github.com/meilisearch/meilisearch-go",
    "github.com/minio/minio-go",
    "github.com/satori/go.uuid",
    "github.com/shopspring/decimal",
    "github.com/Masterminds/semver",
    "github.com/Masterminds/sprig",
    "github.com/pelletier/go-toml",
    "gopkg.in/yaml.v3",
]

# Top popular RubyGems packages for fuzzy matching suggestions
TOP_RUBYGEMS_PACKAGES: list[str] = [
    "rails", "rake", "bundler", "nokogiri", "rspec", "puma", "devise",
    "sidekiq", "pg", "redis", "rack", "sinatra", "activerecord", "activesupport",
    "actionpack", "actionmailer", "actioncable", "activejob", "activestorage",
    "railties", "sprockets", "turbo-rails", "stimulus-rails", "importmap-rails",
    "jbuilder", "bootsnap", "tzinfo", "concurrent-ruby", "i18n", "minitest",
    "thor", "erubi", "loofah", "rails-html-sanitizer", "globalid", "marcel",
    "net-smtp", "net-imap", "net-pop", "timeout", "mail", "mini_mime",
    "faraday", "httparty", "rest-client", "typhoeus", "excon",
    "json", "multi_json", "oj", "yajl-ruby", "msgpack",
    "rspec-core", "rspec-expectations", "rspec-mocks", "rspec-support",
    "rubocop", "rubocop-rails", "rubocop-rspec", "rubocop-performance",
    "factory_bot", "factory_bot_rails", "faker", "capybara", "selenium-webdriver",
    "webmock", "vcr", "simplecov", "shoulda-matchers",
    "aws-sdk-s3", "aws-sdk-core", "aws-sdk-sqs", "aws-sdk-sns",
    "google-cloud-storage", "fog-aws",
    "pundit", "cancancan", "omniauth", "bcrypt", "jwt",
    "kaminari", "will_paginate", "pagy",
    "slim", "haml", "sassc", "sassc-rails",
    "activeadmin", "administrate", "ransack",
    "paper_trail", "audited", "acts_as_paranoid",
    "draper", "cell", "trailblazer",
    "grape", "grape-entity", "graphql", "graphql-ruby",
    "delayed_job", "resque", "good_job", "solid_queue",
    "whenever", "clockwork", "rufus-scheduler",
    "carrierwave", "shrine", "dragonfly", "paperclip",
    "prawn", "wicked_pdf", "grover",
    "sentry-ruby", "sentry-rails", "newrelic_rpm", "datadog",
    "pry", "pry-byebug", "byebug", "debug",
    "dotenv", "figaro", "config",
    "annotate", "bullet", "rack-mini-profiler",
    "net-http", "mechanize", "watir",
    "mongoid", "sequel", "rom-rb",
    "dry-types", "dry-validation", "dry-monads",
    "sorbet", "sorbet-runtime", "steep",
    "rubygems-update", "rdoc", "irb",
]

# Top popular Packagist (PHP) packages for fuzzy matching suggestions
TOP_PACKAGIST_PACKAGES: list[str] = [
    "laravel/framework", "symfony/symfony", "guzzlehttp/guzzle",
    "monolog/monolog", "phpunit/phpunit", "doctrine/orm",
    "nesbot/carbon", "fideloper/proxy", "vlucas/phpdotenv",
    "psr/log", "psr/http-message", "psr/container", "psr/cache",
    "symfony/console", "symfony/http-foundation", "symfony/routing",
    "symfony/event-dispatcher", "symfony/process", "symfony/finder",
    "symfony/yaml", "symfony/var-dumper", "symfony/debug",
    "symfony/translation", "symfony/http-kernel", "symfony/mime",
    "symfony/polyfill-mbstring", "symfony/polyfill-ctype",
    "illuminate/database", "illuminate/support", "illuminate/container",
    "illuminate/events", "illuminate/http", "illuminate/routing",
    "illuminate/queue", "illuminate/cache", "illuminate/auth",
    "league/flysystem", "league/commonmark", "league/csv",
    "league/oauth2-client", "league/fractal", "league/plates",
    "ramsey/uuid", "ramsey/collection",
    "nikic/php-parser", "nikic/fast-route",
    "filp/whoops", "barryvdh/laravel-debugbar",
    "phpmailer/phpmailer", "swiftmailer/swiftmailer",
    "predis/predis", "phpredis/phpredis",
    "aws/aws-sdk-php", "google/cloud", "azure/storage-blob",
    "spatie/laravel-permission", "spatie/laravel-medialibrary",
    "spatie/laravel-backup", "spatie/laravel-activitylog",
    "tymon/jwt-auth", "lcobucci/jwt",
    "intervention/image", "barryvdh/laravel-dompdf",
    "phpstan/phpstan", "psalm/psalm", "squizlabs/php_codesniffer",
    "friendsofphp/php-cs-fixer", "rector/rector",
    "mockery/mockery", "pestphp/pest",
    "fakerphp/faker", "nunomaduro/collision",
    "dompdf/dompdf", "mpdf/mpdf", "tecnickcom/tcpdf",
    "elasticsearch/elasticsearch", "algolia/algoliasearch-client-php",
    "sentry/sentry-laravel", "bugsnag/bugsnag-laravel",
    "stripe/stripe-php", "paypal/rest-api-sdk-php",
    "twilio/sdk", "vonage/client-core",
    "firebase/php-jwt", "web-token/jwt-framework",
    "composer/composer", "composer/semver",
    "twig/twig", "blade-ui-kit/blade-icons",
    "livewire/livewire", "inertiajs/inertia-laravel",
]

# Top popular Maven Central packages for fuzzy matching suggestions
TOP_MAVEN_PACKAGES: list[str] = [
    "com.google.guava:guava", "com.google.code.gson:gson",
    "org.apache.commons:commons-lang3", "commons-io:commons-io",
    "org.apache.httpcomponents:httpclient", "org.apache.commons:commons-collections4",
    "junit:junit", "org.junit.jupiter:junit-jupiter",
    "org.mockito:mockito-core", "org.assertj:assertj-core",
    "org.slf4j:slf4j-api", "ch.qos.logback:logback-classic",
    "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
    "com.fasterxml.jackson.core:jackson-databind",
    "com.fasterxml.jackson.core:jackson-core",
    "com.fasterxml.jackson.core:jackson-annotations",
    "org.projectlombok:lombok", "javax.annotation:javax.annotation-api",
    "org.springframework:spring-core", "org.springframework:spring-context",
    "org.springframework:spring-web", "org.springframework:spring-webmvc",
    "org.springframework.boot:spring-boot-starter",
    "org.springframework.boot:spring-boot-starter-web",
    "org.springframework.boot:spring-boot-starter-data-jpa",
    "org.springframework.boot:spring-boot-starter-test",
    "org.springframework.boot:spring-boot-starter-security",
    "org.springframework.security:spring-security-core",
    "io.quarkus:quarkus-core", "io.micronaut:micronaut-core",
    "jakarta.servlet:jakarta.servlet-api", "javax.servlet:javax.servlet-api",
    "com.squareup.okhttp3:okhttp", "com.squareup.retrofit2:retrofit",
    "io.netty:netty-all", "io.grpc:grpc-core",
    "org.apache.kafka:kafka-clients", "com.rabbitmq:amqp-client",
    "mysql:mysql-connector-java", "org.postgresql:postgresql",
    "com.h2database:h2", "org.xerial:sqlite-jdbc",
    "org.hibernate:hibernate-core", "org.mybatis:mybatis",
    "com.zaxxer:HikariCP", "org.flywaydb:flyway-core",
    "org.liquibase:liquibase-core",
    "io.jsonwebtoken:jjwt-api", "com.auth0:java-jwt",
    "org.apache.maven.plugins:maven-compiler-plugin",
    "com.google.protobuf:protobuf-java",
    "io.swagger.core.v3:swagger-core",
    "org.mapstruct:mapstruct", "ma.glasnost.orika:orika-core",
    "com.google.cloud:google-cloud-storage",
    "software.amazon.awssdk:s3", "software.amazon.awssdk:dynamodb",
    "org.testcontainers:testcontainers", "org.testcontainers:junit-jupiter",
    "io.micrometer:micrometer-core", "io.prometheus:simpleclient",
    "org.apache.poi:poi", "org.apache.poi:poi-ooxml",
    "com.itextpdf:itext7-core",
    "io.projectreactor:reactor-core", "io.reactivex.rxjava3:rxjava",
]

# Top popular NuGet packages for fuzzy matching suggestions
TOP_NUGET_PACKAGES: list[str] = [
    "Newtonsoft.Json", "System.Text.Json",
    "Microsoft.Extensions.DependencyInjection",
    "Microsoft.Extensions.Logging", "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Http",
    "Microsoft.EntityFrameworkCore", "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.Design",
    "Microsoft.AspNetCore.Mvc.Core", "Microsoft.AspNetCore.Authentication.JwtBearer",
    "Serilog", "Serilog.Sinks.Console", "Serilog.Sinks.File",
    "NLog", "log4net",
    "AutoMapper", "AutoMapper.Extensions.Microsoft.DependencyInjection",
    "FluentValidation", "FluentValidation.AspNetCore",
    "MediatR", "MediatR.Extensions.Microsoft.DependencyInjection",
    "Dapper", "Npgsql", "MySqlConnector", "StackExchange.Redis",
    "Moq", "NSubstitute", "FakeItEasy",
    "xunit", "xunit.runner.visualstudio", "NUnit", "NUnit3TestAdapter",
    "FluentAssertions", "Shouldly", "Bogus",
    "Polly", "Polly.Extensions.Http",
    "RestSharp", "Flurl", "Flurl.Http",
    "Swashbuckle.AspNetCore", "NSwag.AspNetCore",
    "Hangfire", "Hangfire.Core", "Quartz",
    "MassTransit", "MassTransit.RabbitMQ",
    "RabbitMQ.Client", "Confluent.Kafka",
    "AWSSDK.S3", "AWSSDK.Core", "AWSSDK.SQS",
    "Google.Cloud.Storage.V1", "Azure.Storage.Blobs",
    "Microsoft.Azure.Cosmos",
    "Grpc.Net.Client", "Grpc.AspNetCore",
    "IdentityServer4", "Duende.IdentityServer",
    "BCrypt.Net-Next", "Microsoft.AspNetCore.Identity",
    "Mapster", "Riok.Mapperly",
    "CsvHelper", "EPPlus", "ClosedXML",
    "HtmlAgilityPack", "AngleSharp",
    "SixLabors.ImageSharp", "QRCoder",
    "Humanizer", "Humanizer.Core",
    "Scrutor", "Autofac", "SimpleInjector",
    "BenchmarkDotNet", "coverlet.collector",
    "SignalR", "Microsoft.AspNetCore.SignalR",
    "MongoDB.Driver", "LiteDB",
    "Microsoft.Extensions.Caching.Memory",
    "Microsoft.Extensions.Caching.StackExchangeRedis",
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


def suggest_crates_package(crate: str) -> str:
    """Suggest similar crates.io package names."""
    return suggest_similar_package(crate, TOP_CRATES_PACKAGES)


def suggest_go_module(module: str) -> str:
    """Suggest similar Go module names."""
    return suggest_similar_package(module, TOP_GO_MODULES)


def suggest_rubygems_package(gem: str) -> str:
    """Suggest similar RubyGems package names."""
    return suggest_similar_package(gem, TOP_RUBYGEMS_PACKAGES)


def suggest_packagist_package(package: str) -> str:
    """Suggest similar Packagist (PHP) package names."""
    return suggest_similar_package(package, TOP_PACKAGIST_PACKAGES)


def suggest_maven_package(artifact: str) -> str:
    """Suggest similar Maven Central package names."""
    return suggest_similar_package(artifact, TOP_MAVEN_PACKAGES)


def suggest_nuget_package(package: str) -> str:
    """Suggest similar NuGet package names."""
    return suggest_similar_package(package, TOP_NUGET_PACKAGES)
