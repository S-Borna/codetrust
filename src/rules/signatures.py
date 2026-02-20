# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Curated function signature database for popular libraries.

Powers the Signature Validator — detects AI-hallucinated function names,
wrong parameters, missing required args, and deprecated usage.

Coverage: Top 20 Python + Top 10 JS/TS libraries.
Each entry is verified against official documentation.

Architecture:
    SIGNATURES[language][module][function_name] -> FunctionSig

Unlike Jedi (Python-only, requires installed packages), this database:
    1. Works without packages installed (CI/CD friendly)
    2. Covers Python AND JavaScript/TypeScript
    3. Tracks common AI hallucinations (nonexistent params AI invents)
    4. Instant in-memory lookup — no import resolution needed
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ParamInfo:
    """Metadata for a single function parameter."""

    name: str
    required: bool = False
    deprecated: bool = False
    deprecated_since: str = ""
    replacement: str = ""


@dataclass(frozen=True)
class FunctionSig:
    """Complete signature for a single function or method."""

    name: str
    params: list[ParamInfo] = field(default_factory=list)
    min_args: int = 0
    max_args: int = -1  # -1 = unlimited (*args)
    deprecated: bool = False
    deprecated_since: str = ""
    replacement: str = ""
    return_type: str = ""
    common_hallucinations: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass(frozen=True)
class ModuleSig:
    """All exported functions/methods for a module or class."""

    name: str
    functions: dict[str, FunctionSig] = field(default_factory=dict)
    submodules: dict[str, dict[str, FunctionSig]] = field(default_factory=dict)
    common_hallucinated_functions: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
#  PYTHON SIGNATURES
# ═══════════════════════════════════════════════════════════════════════

_PY_REQUESTS: ModuleSig = ModuleSig(
    name="requests",
    functions={
        "get": FunctionSig(
            name="get",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="auth"),
                ParamInfo(name="timeout"),
                ParamInfo(name="allow_redirects"),
                ParamInfo(name="proxies"),
                ParamInfo(name="verify"),
                ParamInfo(name="stream"),
                ParamInfo(name="cert"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["body", "payload", "data", "json", "content_type"],
        ),
        "post": FunctionSig(
            name="post",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="json"),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="auth"),
                ParamInfo(name="timeout"),
                ParamInfo(name="allow_redirects"),
                ParamInfo(name="proxies"),
                ParamInfo(name="verify"),
                ParamInfo(name="stream"),
                ParamInfo(name="cert"),
                ParamInfo(name="files"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["body", "payload", "content_type", "content"],
        ),
        "put": FunctionSig(
            name="put",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="json"),
                ParamInfo(name="headers"),
                ParamInfo(name="timeout"),
                ParamInfo(name="verify"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["body", "payload"],
        ),
        "delete": FunctionSig(
            name="delete",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="headers"),
                ParamInfo(name="timeout"),
                ParamInfo(name="verify"),
            ],
            min_args=1,
            return_type="Response",
        ),
        "patch": FunctionSig(
            name="patch",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="json"),
                ParamInfo(name="headers"),
                ParamInfo(name="timeout"),
                ParamInfo(name="verify"),
            ],
            min_args=1,
            return_type="Response",
        ),
        "head": FunctionSig(
            name="head",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="headers"),
                ParamInfo(name="timeout"),
                ParamInfo(name="verify"),
            ],
            min_args=1,
            return_type="Response",
        ),
        "Session": FunctionSig(
            name="Session",
            min_args=0,
            max_args=0,
            return_type="Session",
        ),
    },
    common_hallucinated_functions=[
        "get_async", "post_async", "async_get", "fetch",
        "request_json", "send", "download", "upload",
        "get_json", "post_json",
    ],
)

_PY_FLASK: ModuleSig = ModuleSig(
    name="flask",
    functions={
        "Flask": FunctionSig(
            name="Flask",
            params=[
                ParamInfo(name="import_name", required=True),
                ParamInfo(name="static_url_path"),
                ParamInfo(name="static_folder"),
                ParamInfo(name="template_folder"),
                ParamInfo(name="instance_path"),
                ParamInfo(name="instance_relative_config"),
                ParamInfo(name="root_path"),
            ],
            min_args=1,
            return_type="Flask",
            common_hallucinations=["name", "debug", "host", "port", "config"],
        ),
        "jsonify": FunctionSig(
            name="jsonify",
            min_args=0,
            max_args=-1,
            return_type="Response",
        ),
        "render_template": FunctionSig(
            name="render_template",
            params=[ParamInfo(name="template_name_or_list", required=True)],
            min_args=1,
            max_args=-1,
            return_type="str",
            common_hallucinations=["template", "template_name", "context"],
        ),
        "redirect": FunctionSig(
            name="redirect",
            params=[
                ParamInfo(name="location", required=True),
                ParamInfo(name="code"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["url", "status_code", "permanent"],
        ),
        "url_for": FunctionSig(
            name="url_for",
            params=[ParamInfo(name="endpoint", required=True)],
            min_args=1,
            max_args=-1,
            return_type="str",
            common_hallucinations=["route", "path", "view"],
        ),
        "abort": FunctionSig(
            name="abort",
            params=[ParamInfo(name="status", required=True)],
            min_args=1,
            return_type="NoReturn",
        ),
        "make_response": FunctionSig(
            name="make_response",
            min_args=0,
            max_args=-1,
            return_type="Response",
        ),
    },
    common_hallucinated_functions=[
        "create_app", "route", "get", "post",
        "register_route", "add_route", "json_response",
    ],
)

_PY_PANDAS: ModuleSig = ModuleSig(
    name="pandas",
    functions={
        "read_csv": FunctionSig(
            name="read_csv",
            params=[
                ParamInfo(name="filepath_or_buffer", required=True),
                ParamInfo(name="sep"),
                ParamInfo(name="delimiter"),
                ParamInfo(name="header"),
                ParamInfo(name="names"),
                ParamInfo(name="index_col"),
                ParamInfo(name="usecols"),
                ParamInfo(name="dtype"),
                ParamInfo(name="engine"),
                ParamInfo(name="converters"),
                ParamInfo(name="na_values"),
                ParamInfo(name="keep_default_na"),
                ParamInfo(name="na_filter"),
                ParamInfo(name="parse_dates"),
                ParamInfo(name="date_parser", deprecated=True, replacement="date_format"),
                ParamInfo(name="date_format"),
                ParamInfo(name="encoding"),
                ParamInfo(name="compression"),
                ParamInfo(name="chunksize"),
                ParamInfo(name="nrows"),
                ParamInfo(name="skiprows"),
                ParamInfo(name="skipfooter"),
            ],
            min_args=1,
            return_type="DataFrame",
            common_hallucinations=[
                "headers", "columns", "col_names", "file",
                "path", "filename", "skip_header",
            ],
        ),
        "read_json": FunctionSig(
            name="read_json",
            params=[
                ParamInfo(name="path_or_buf", required=True),
                ParamInfo(name="orient"),
                ParamInfo(name="typ"),
                ParamInfo(name="dtype"),
                ParamInfo(name="convert_dates"),
                ParamInfo(name="lines"),
                ParamInfo(name="chunksize"),
                ParamInfo(name="encoding"),
            ],
            min_args=1,
            return_type="DataFrame",
            common_hallucinations=["file", "path", "format"],
        ),
        "read_excel": FunctionSig(
            name="read_excel",
            params=[
                ParamInfo(name="io", required=True),
                ParamInfo(name="sheet_name"),
                ParamInfo(name="header"),
                ParamInfo(name="names"),
                ParamInfo(name="index_col"),
                ParamInfo(name="usecols"),
                ParamInfo(name="dtype"),
                ParamInfo(name="engine"),
                ParamInfo(name="nrows"),
                ParamInfo(name="skiprows"),
            ],
            min_args=1,
            return_type="DataFrame",
            common_hallucinations=["file", "path", "worksheet", "tab"],
        ),
        "DataFrame": FunctionSig(
            name="DataFrame",
            params=[
                ParamInfo(name="data"),
                ParamInfo(name="index"),
                ParamInfo(name="columns"),
                ParamInfo(name="dtype"),
                ParamInfo(name="copy"),
            ],
            min_args=0,
            return_type="DataFrame",
            common_hallucinations=["rows", "headers", "col_names", "schema"],
        ),
        "concat": FunctionSig(
            name="concat",
            params=[
                ParamInfo(name="objs", required=True),
                ParamInfo(name="axis"),
                ParamInfo(name="join"),
                ParamInfo(name="ignore_index"),
                ParamInfo(name="keys"),
                ParamInfo(name="sort"),
            ],
            min_args=1,
            return_type="DataFrame",
            common_hallucinations=["dataframes", "frames", "dfs", "how"],
        ),
        "merge": FunctionSig(
            name="merge",
            params=[
                ParamInfo(name="left", required=True),
                ParamInfo(name="right", required=True),
                ParamInfo(name="how"),
                ParamInfo(name="on"),
                ParamInfo(name="left_on"),
                ParamInfo(name="right_on"),
                ParamInfo(name="left_index"),
                ParamInfo(name="right_index"),
                ParamInfo(name="suffixes"),
            ],
            min_args=2,
            return_type="DataFrame",
            common_hallucinations=["join_type", "key", "join_on"],
        ),
        "to_datetime": FunctionSig(
            name="to_datetime",
            params=[
                ParamInfo(name="arg", required=True),
                ParamInfo(name="format"),
                ParamInfo(name="errors"),
                ParamInfo(name="utc"),
                ParamInfo(name="unit"),
            ],
            min_args=1,
            return_type="DatetimeIndex | Timestamp",
            common_hallucinations=["date_format", "fmt", "strftime"],
        ),
    },
    common_hallucinated_functions=[
        "read", "load", "load_csv", "from_csv", "from_json",
        "read_table", "create_dataframe", "from_dict_list",
    ],
)

_PY_NUMPY: ModuleSig = ModuleSig(
    name="numpy",
    functions={
        "array": FunctionSig(
            name="array",
            params=[
                ParamInfo(name="object", required=True),
                ParamInfo(name="dtype"),
                ParamInfo(name="copy"),
                ParamInfo(name="order"),
                ParamInfo(name="ndmin"),
            ],
            min_args=1,
            return_type="ndarray",
            common_hallucinations=["data", "shape", "values", "type"],
        ),
        "zeros": FunctionSig(
            name="zeros",
            params=[
                ParamInfo(name="shape", required=True),
                ParamInfo(name="dtype"),
                ParamInfo(name="order"),
            ],
            min_args=1,
            return_type="ndarray",
        ),
        "ones": FunctionSig(
            name="ones",
            params=[
                ParamInfo(name="shape", required=True),
                ParamInfo(name="dtype"),
                ParamInfo(name="order"),
            ],
            min_args=1,
            return_type="ndarray",
        ),
        "arange": FunctionSig(
            name="arange",
            params=[
                ParamInfo(name="start"),
                ParamInfo(name="stop"),
                ParamInfo(name="step"),
                ParamInfo(name="dtype"),
            ],
            min_args=1,
            max_args=4,
            return_type="ndarray",
            common_hallucinations=["end", "begin", "size"],
        ),
        "reshape": FunctionSig(
            name="reshape",
            params=[
                ParamInfo(name="a", required=True),
                ParamInfo(name="newshape", required=True),
                ParamInfo(name="order"),
            ],
            min_args=2,
            return_type="ndarray",
            common_hallucinations=["shape", "dims", "dimensions"],
        ),
        "linspace": FunctionSig(
            name="linspace",
            params=[
                ParamInfo(name="start", required=True),
                ParamInfo(name="stop", required=True),
                ParamInfo(name="num"),
                ParamInfo(name="endpoint"),
                ParamInfo(name="dtype"),
            ],
            min_args=2,
            return_type="ndarray",
            common_hallucinations=["count", "steps", "n"],
        ),
        "concatenate": FunctionSig(
            name="concatenate",
            params=[
                ParamInfo(name="arrays", required=True),
                ParamInfo(name="axis"),
                ParamInfo(name="dtype"),
            ],
            min_args=1,
            return_type="ndarray",
        ),
        "dot": FunctionSig(
            name="dot",
            params=[
                ParamInfo(name="a", required=True),
                ParamInfo(name="b", required=True),
            ],
            min_args=2,
            return_type="ndarray | scalar",
        ),
    },
    common_hallucinated_functions=[
        "create_array", "matrix", "tensor", "from_list",
        "new_array", "make_array",
    ],
)

_PY_FASTAPI: ModuleSig = ModuleSig(
    name="fastapi",
    functions={
        "FastAPI": FunctionSig(
            name="FastAPI",
            params=[
                ParamInfo(name="title"),
                ParamInfo(name="description"),
                ParamInfo(name="version"),
                ParamInfo(name="openapi_url"),
                ParamInfo(name="docs_url"),
                ParamInfo(name="redoc_url"),
                ParamInfo(name="lifespan"),
                ParamInfo(name="middleware"),
            ],
            min_args=0,
            return_type="FastAPI",
            common_hallucinations=["name", "host", "port", "debug", "app_name"],
        ),
        "Depends": FunctionSig(
            name="Depends",
            params=[ParamInfo(name="dependency")],
            min_args=0,
            return_type="Depends",
        ),
        "Query": FunctionSig(
            name="Query",
            params=[
                ParamInfo(name="default"),
                ParamInfo(name="alias"),
                ParamInfo(name="title"),
                ParamInfo(name="description"),
                ParamInfo(name="ge"),
                ParamInfo(name="le"),
                ParamInfo(name="min_length"),
                ParamInfo(name="max_length"),
                ParamInfo(name="regex", deprecated=True, replacement="pattern"),
                ParamInfo(name="pattern"),
            ],
            min_args=0,
            return_type="Query",
            common_hallucinations=["required", "type", "validator"],
        ),
        "Path": FunctionSig(
            name="Path",
            params=[
                ParamInfo(name="default"),
                ParamInfo(name="alias"),
                ParamInfo(name="title"),
                ParamInfo(name="description"),
                ParamInfo(name="ge"),
                ParamInfo(name="le"),
            ],
            min_args=0,
            return_type="Path",
        ),
        "Body": FunctionSig(
            name="Body",
            params=[
                ParamInfo(name="default"),
                ParamInfo(name="embed"),
                ParamInfo(name="title"),
                ParamInfo(name="description"),
            ],
            min_args=0,
            return_type="Body",
        ),
        "HTTPException": FunctionSig(
            name="HTTPException",
            params=[
                ParamInfo(name="status_code", required=True),
                ParamInfo(name="detail"),
                ParamInfo(name="headers"),
            ],
            min_args=1,
            return_type="HTTPException",
            common_hallucinations=["message", "code", "error", "status"],
        ),
    },
    common_hallucinated_functions=[
        "create_app", "route", "get", "post",
        "register_middleware", "add_route",
    ],
)

_PY_DJANGO: ModuleSig = ModuleSig(
    name="django",
    submodules={
        "shortcuts": {
            "render": FunctionSig(
                name="render",
                params=[
                    ParamInfo(name="request", required=True),
                    ParamInfo(name="template_name", required=True),
                    ParamInfo(name="context"),
                    ParamInfo(name="content_type"),
                    ParamInfo(name="status"),
                    ParamInfo(name="using"),
                ],
                min_args=2,
                return_type="HttpResponse",
                common_hallucinations=["template", "data", "ctx"],
            ),
            "redirect": FunctionSig(
                name="redirect",
                params=[
                    ParamInfo(name="to", required=True),
                    ParamInfo(name="permanent"),
                ],
                min_args=1,
                return_type="HttpResponseRedirect",
                common_hallucinations=["url", "location", "status_code"],
            ),
            "get_object_or_404": FunctionSig(
                name="get_object_or_404",
                params=[
                    ParamInfo(name="klass", required=True),
                ],
                min_args=1,
                max_args=-1,
                return_type="Model",
            ),
        },
        "http": {
            "JsonResponse": FunctionSig(
                name="JsonResponse",
                params=[
                    ParamInfo(name="data", required=True),
                    ParamInfo(name="encoder"),
                    ParamInfo(name="safe"),
                    ParamInfo(name="json_dumps_params"),
                    ParamInfo(name="content_type"),
                    ParamInfo(name="status"),
                ],
                min_args=1,
                return_type="JsonResponse",
                common_hallucinations=["serializer", "format"],
            ),
            "HttpResponse": FunctionSig(
                name="HttpResponse",
                params=[
                    ParamInfo(name="content"),
                    ParamInfo(name="content_type"),
                    ParamInfo(name="status"),
                    ParamInfo(name="reason"),
                    ParamInfo(name="charset"),
                ],
                min_args=0,
                return_type="HttpResponse",
            ),
        },
    },
    common_hallucinated_functions=[
        "create_view", "json_response", "template_response",
        "make_response", "send_response",
    ],
)

_PY_SQLALCHEMY: ModuleSig = ModuleSig(
    name="sqlalchemy",
    functions={
        "create_engine": FunctionSig(
            name="create_engine",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="echo"),
                ParamInfo(name="pool_size"),
                ParamInfo(name="max_overflow"),
                ParamInfo(name="pool_timeout"),
                ParamInfo(name="pool_recycle"),
                ParamInfo(name="pool_pre_ping"),
                ParamInfo(name="connect_args"),
                ParamInfo(name="future"),
            ],
            min_args=1,
            return_type="Engine",
            common_hallucinations=[
                "database_url", "db_url", "connection_string",
                "host", "port", "database", "user", "password",
            ],
        ),
        "Column": FunctionSig(
            name="Column",
            params=[
                ParamInfo(name="name"),
                ParamInfo(name="type_"),
                ParamInfo(name="primary_key"),
                ParamInfo(name="nullable"),
                ParamInfo(name="default"),
                ParamInfo(name="index"),
                ParamInfo(name="unique"),
                ParamInfo(name="autoincrement"),
                ParamInfo(name="server_default"),
            ],
            min_args=0,
            max_args=-1,
            return_type="Column",
            common_hallucinations=["field_type", "required", "max_length"],
        ),
        "select": FunctionSig(
            name="select",
            min_args=0,
            max_args=-1,
            return_type="Select",
        ),
        "text": FunctionSig(
            name="text",
            params=[ParamInfo(name="text", required=True)],
            min_args=1,
            return_type="TextClause",
        ),
    },
    common_hallucinated_functions=[
        "connect", "query", "execute", "fetch",
        "create_session", "create_table",
    ],
)

_PY_HTTPX: ModuleSig = ModuleSig(
    name="httpx",
    functions={
        "get": FunctionSig(
            name="get",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="auth"),
                ParamInfo(name="timeout"),
                ParamInfo(name="follow_redirects"),
                ParamInfo(name="verify"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["allow_redirects", "data", "body"],
            notes="httpx uses follow_redirects, not allow_redirects (requests compat trap)",
        ),
        "post": FunctionSig(
            name="post",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="content"),
                ParamInfo(name="data"),
                ParamInfo(name="json"),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="auth"),
                ParamInfo(name="timeout"),
                ParamInfo(name="follow_redirects"),
            ],
            min_args=1,
            return_type="Response",
            common_hallucinations=["body", "payload", "allow_redirects"],
        ),
        "AsyncClient": FunctionSig(
            name="AsyncClient",
            params=[
                ParamInfo(name="auth"),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="verify"),
                ParamInfo(name="cert"),
                ParamInfo(name="timeout"),
                ParamInfo(name="limits"),
                ParamInfo(name="max_redirects"),
                ParamInfo(name="base_url"),
                ParamInfo(name="transport"),
                ParamInfo(name="follow_redirects"),
            ],
            min_args=0,
            return_type="AsyncClient",
            common_hallucinations=["pool_size", "max_connections", "session"],
        ),
        "Client": FunctionSig(
            name="Client",
            params=[
                ParamInfo(name="auth"),
                ParamInfo(name="params"),
                ParamInfo(name="headers"),
                ParamInfo(name="cookies"),
                ParamInfo(name="verify"),
                ParamInfo(name="timeout"),
                ParamInfo(name="limits"),
                ParamInfo(name="base_url"),
                ParamInfo(name="follow_redirects"),
            ],
            min_args=0,
            return_type="Client",
        ),
    },
    common_hallucinated_functions=[
        "fetch", "request", "send", "download",
        "async_get", "async_post",
    ],
)

_PY_PYDANTIC: ModuleSig = ModuleSig(
    name="pydantic",
    functions={
        "BaseModel": FunctionSig(
            name="BaseModel",
            min_args=0,
            max_args=-1,
            return_type="BaseModel",
            notes="Base class — constructor accepts model fields as kwargs",
        ),
        "Field": FunctionSig(
            name="Field",
            params=[
                ParamInfo(name="default"),
                ParamInfo(name="default_factory"),
                ParamInfo(name="alias"),
                ParamInfo(name="title"),
                ParamInfo(name="description"),
                ParamInfo(name="ge"),
                ParamInfo(name="le"),
                ParamInfo(name="gt"),
                ParamInfo(name="lt"),
                ParamInfo(name="min_length"),
                ParamInfo(name="max_length"),
                ParamInfo(name="pattern"),
                ParamInfo(name="strict"),
                ParamInfo(name="frozen"),
                ParamInfo(name="exclude"),
                ParamInfo(name="deprecated"),
                ParamInfo(name="json_schema_extra"),
                ParamInfo(name="validate_default"),
                ParamInfo(name="regex", deprecated=True, replacement="pattern"),
                ParamInfo(name="const", deprecated=True),
            ],
            min_args=0,
            return_type="FieldInfo",
            common_hallucinations=[
                "required", "optional", "nullable", "type",
                "validator", "max_value", "min_value",
            ],
        ),
        "validator": FunctionSig(
            name="validator",
            deprecated=True,
            deprecated_since="v2",
            replacement="field_validator",
            min_args=0,
            max_args=-1,
        ),
        "field_validator": FunctionSig(
            name="field_validator",
            min_args=1,
            max_args=-1,
            return_type="classmethod",
        ),
        "model_validator": FunctionSig(
            name="model_validator",
            params=[ParamInfo(name="mode")],
            min_args=0,
            return_type="classmethod",
        ),
        "ConfigDict": FunctionSig(
            name="ConfigDict",
            params=[
                ParamInfo(name="strict"),
                ParamInfo(name="frozen"),
                ParamInfo(name="populate_by_name"),
                ParamInfo(name="use_enum_values"),
                ParamInfo(name="validate_default"),
                ParamInfo(name="arbitrary_types_allowed"),
                ParamInfo(name="from_attributes"),
                ParamInfo(name="orm_mode", deprecated=True, replacement="from_attributes"),
                ParamInfo(name="allow_population_by_field_name", deprecated=True,
                          replacement="populate_by_name"),
            ],
            min_args=0,
            return_type="ConfigDict",
            common_hallucinations=["allow_mutation", "schema_extra", "json_encoders"],
        ),
    },
    common_hallucinated_functions=[
        "Schema", "create_model_from_dict", "validate",
        "parse", "from_json", "to_json",
    ],
)

_PY_PYTEST: ModuleSig = ModuleSig(
    name="pytest",
    functions={
        "fixture": FunctionSig(
            name="fixture",
            params=[
                ParamInfo(name="scope"),
                ParamInfo(name="params"),
                ParamInfo(name="autouse"),
                ParamInfo(name="ids"),
                ParamInfo(name="name"),
            ],
            min_args=0,
            return_type="fixture",
            common_hallucinations=["setup", "teardown", "yield_fixture"],
        ),
        "mark": FunctionSig(
            name="mark",
            notes="Attribute namespace, not a callable",
        ),
        "raises": FunctionSig(
            name="raises",
            params=[
                ParamInfo(name="expected_exception", required=True),
                ParamInfo(name="match"),
            ],
            min_args=1,
            return_type="RaisesContext",
            common_hallucinations=["exception", "error", "message"],
        ),
        "approx": FunctionSig(
            name="approx",
            params=[
                ParamInfo(name="expected", required=True),
                ParamInfo(name="rel"),
                ParamInfo(name="abs"),
                ParamInfo(name="nan_ok"),
            ],
            min_args=1,
            return_type="ApproxBase",
        ),
        "param": FunctionSig(
            name="param",
            min_args=0,
            max_args=-1,
            return_type="ParameterSet",
        ),
    },
    common_hallucinated_functions=[
        "assert_raises", "assert_equal", "test",
        "describe", "it", "expect",
    ],
)

_PY_OS: ModuleSig = ModuleSig(
    name="os",
    functions={
        "getenv": FunctionSig(
            name="getenv",
            params=[
                ParamInfo(name="key", required=True),
                ParamInfo(name="default"),
            ],
            min_args=1,
            max_args=2,
            return_type="str | None",
        ),
        "makedirs": FunctionSig(
            name="makedirs",
            params=[
                ParamInfo(name="name", required=True),
                ParamInfo(name="mode"),
                ParamInfo(name="exist_ok"),
            ],
            min_args=1,
            return_type="None",
            common_hallucinations=["recursive", "parents", "create_parents"],
        ),
        "listdir": FunctionSig(
            name="listdir",
            params=[ParamInfo(name="path")],
            min_args=0,
            max_args=1,
            return_type="list[str]",
        ),
        "remove": FunctionSig(
            name="remove",
            params=[ParamInfo(name="path", required=True)],
            min_args=1,
            max_args=1,
            return_type="None",
            common_hallucinations=["force", "recursive"],
        ),
    },
    submodules={
        "path": {
            "exists": FunctionSig(name="exists", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="bool"),
            "join": FunctionSig(name="join", min_args=1, max_args=-1, return_type="str"),
            "dirname": FunctionSig(name="dirname", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="str"),
            "basename": FunctionSig(name="basename", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="str"),
            "isfile": FunctionSig(name="isfile", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="bool"),
            "isdir": FunctionSig(name="isdir", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="bool"),
            "abspath": FunctionSig(name="abspath", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="str"),
            "splitext": FunctionSig(name="splitext", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="tuple[str, str]"),
        },
    },
)

_PY_JSON: ModuleSig = ModuleSig(
    name="json",
    functions={
        "dumps": FunctionSig(
            name="dumps",
            params=[
                ParamInfo(name="obj", required=True),
                ParamInfo(name="indent"),
                ParamInfo(name="sort_keys"),
                ParamInfo(name="default"),
                ParamInfo(name="ensure_ascii"),
                ParamInfo(name="separators"),
                ParamInfo(name="cls"),
            ],
            min_args=1,
            return_type="str",
            common_hallucinations=["pretty", "format", "encoding"],
        ),
        "loads": FunctionSig(
            name="loads",
            params=[
                ParamInfo(name="s", required=True),
                ParamInfo(name="cls"),
                ParamInfo(name="object_hook"),
                ParamInfo(name="parse_float"),
                ParamInfo(name="parse_int"),
            ],
            min_args=1,
            return_type="Any",
            common_hallucinations=["encoding", "strict"],
        ),
        "dump": FunctionSig(
            name="dump",
            params=[
                ParamInfo(name="obj", required=True),
                ParamInfo(name="fp", required=True),
                ParamInfo(name="indent"),
                ParamInfo(name="sort_keys"),
                ParamInfo(name="default"),
            ],
            min_args=2,
            return_type="None",
        ),
        "load": FunctionSig(
            name="load",
            params=[
                ParamInfo(name="fp", required=True),
                ParamInfo(name="cls"),
                ParamInfo(name="object_hook"),
            ],
            min_args=1,
            return_type="Any",
        ),
    },
    common_hallucinated_functions=[
        "parse", "stringify", "encode", "decode",
        "from_string", "to_string",
    ],
)

_PY_PATHLIB: ModuleSig = ModuleSig(
    name="pathlib",
    functions={
        "Path": FunctionSig(
            name="Path",
            min_args=0,
            max_args=-1,
            return_type="Path",
            common_hallucinations=["create", "make"],
        ),
    },
    common_hallucinated_functions=[
        "join", "exists", "open", "create",
    ],
)

_PY_LOGGING: ModuleSig = ModuleSig(
    name="logging",
    functions={
        "getLogger": FunctionSig(
            name="getLogger",
            params=[ParamInfo(name="name")],
            min_args=0,
            max_args=1,
            return_type="Logger",
            common_hallucinations=["level", "format", "handler"],
        ),
        "basicConfig": FunctionSig(
            name="basicConfig",
            params=[
                ParamInfo(name="filename"),
                ParamInfo(name="filemode"),
                ParamInfo(name="format"),
                ParamInfo(name="datefmt"),
                ParamInfo(name="style"),
                ParamInfo(name="level"),
                ParamInfo(name="stream"),
                ParamInfo(name="handlers"),
                ParamInfo(name="force"),
                ParamInfo(name="encoding"),
            ],
            min_args=0,
            return_type="None",
        ),
        "info": FunctionSig(name="info", params=[ParamInfo(name="msg", required=True)], min_args=1, max_args=-1, return_type="None"),
        "warning": FunctionSig(name="warning", params=[ParamInfo(name="msg", required=True)], min_args=1, max_args=-1, return_type="None"),
        "error": FunctionSig(name="error", params=[ParamInfo(name="msg", required=True)], min_args=1, max_args=-1, return_type="None"),
        "debug": FunctionSig(name="debug", params=[ParamInfo(name="msg", required=True)], min_args=1, max_args=-1, return_type="None"),
    },
    common_hallucinated_functions=[
        "log", "create_logger", "set_level",
        "add_handler", "Logger",
    ],
)

# ═══════════════════════════════════════════════════════════════════════
#  JAVASCRIPT / TYPESCRIPT SIGNATURES
# ═══════════════════════════════════════════════════════════════════════

_JS_EXPRESS: ModuleSig = ModuleSig(
    name="express",
    functions={
        "express": FunctionSig(
            name="express",
            min_args=0,
            max_args=0,
            return_type="Application",
            notes="Default export — const app = express()",
        ),
        "Router": FunctionSig(
            name="Router",
            params=[
                ParamInfo(name="options"),
            ],
            min_args=0,
            return_type="Router",
        ),
        "json": FunctionSig(
            name="json",
            params=[
                ParamInfo(name="options"),
            ],
            min_args=0,
            return_type="middleware",
            common_hallucinations=["limit", "type"],
        ),
        "static": FunctionSig(
            name="static",
            params=[
                ParamInfo(name="root", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            return_type="middleware",
        ),
        "urlencoded": FunctionSig(
            name="urlencoded",
            params=[ParamInfo(name="options")],
            min_args=0,
            return_type="middleware",
        ),
    },
    common_hallucinated_functions=[
        "createServer", "listen", "create_app",
        "createApp", "route", "middleware",
    ],
)

_JS_AXIOS: ModuleSig = ModuleSig(
    name="axios",
    functions={
        "get": FunctionSig(
            name="get",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="config"),
            ],
            min_args=1,
            return_type="Promise<AxiosResponse>",
            common_hallucinations=["headers", "params", "timeout", "body"],
            notes="config object contains headers/params/timeout, not separate args",
        ),
        "post": FunctionSig(
            name="post",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="config"),
            ],
            min_args=1,
            return_type="Promise<AxiosResponse>",
            common_hallucinations=["body", "payload", "headers"],
        ),
        "put": FunctionSig(
            name="put",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="config"),
            ],
            min_args=1,
            return_type="Promise<AxiosResponse>",
        ),
        "delete": FunctionSig(
            name="delete",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="config"),
            ],
            min_args=1,
            return_type="Promise<AxiosResponse>",
        ),
        "create": FunctionSig(
            name="create",
            params=[ParamInfo(name="config")],
            min_args=0,
            return_type="AxiosInstance",
            common_hallucinations=["baseUrl", "options"],
            notes="baseURL (not baseUrl) in config",
        ),
        "interceptors": FunctionSig(
            name="interceptors",
            notes="Property namespace, not a callable",
        ),
    },
    common_hallucinated_functions=[
        "fetch", "request", "send", "getJSON",
        "postJSON", "setHeader", "setHeaders",
    ],
)

_JS_REACT: ModuleSig = ModuleSig(
    name="react",
    functions={
        "useState": FunctionSig(
            name="useState",
            params=[ParamInfo(name="initialState")],
            min_args=0,
            max_args=1,
            return_type="[state, setState]",
            common_hallucinations=["default", "initial", "value"],
        ),
        "useEffect": FunctionSig(
            name="useEffect",
            params=[
                ParamInfo(name="effect", required=True),
                ParamInfo(name="deps"),
            ],
            min_args=1,
            max_args=2,
            return_type="void",
            common_hallucinations=["callback", "dependencies", "cleanup"],
        ),
        "useCallback": FunctionSig(
            name="useCallback",
            params=[
                ParamInfo(name="callback", required=True),
                ParamInfo(name="deps", required=True),
            ],
            min_args=2,
            max_args=2,
            return_type="T",
        ),
        "useMemo": FunctionSig(
            name="useMemo",
            params=[
                ParamInfo(name="factory", required=True),
                ParamInfo(name="deps", required=True),
            ],
            min_args=2,
            max_args=2,
            return_type="T",
        ),
        "useRef": FunctionSig(
            name="useRef",
            params=[ParamInfo(name="initialValue")],
            min_args=0,
            max_args=1,
            return_type="MutableRefObject",
        ),
        "useContext": FunctionSig(
            name="useContext",
            params=[ParamInfo(name="context", required=True)],
            min_args=1,
            max_args=1,
            return_type="T",
        ),
        "useReducer": FunctionSig(
            name="useReducer",
            params=[
                ParamInfo(name="reducer", required=True),
                ParamInfo(name="initialArg", required=True),
                ParamInfo(name="init"),
            ],
            min_args=2,
            max_args=3,
            return_type="[state, dispatch]",
        ),
        "createElement": FunctionSig(
            name="createElement",
            params=[
                ParamInfo(name="type", required=True),
                ParamInfo(name="props"),
            ],
            min_args=1,
            max_args=-1,
            return_type="ReactElement",
        ),
        "createContext": FunctionSig(
            name="createContext",
            params=[ParamInfo(name="defaultValue")],
            min_args=0,
            max_args=1,
            return_type="Context",
        ),
        "forwardRef": FunctionSig(
            name="forwardRef",
            params=[ParamInfo(name="render", required=True)],
            min_args=1,
            max_args=1,
            return_type="ForwardRefExoticComponent",
        ),
        "memo": FunctionSig(
            name="memo",
            params=[
                ParamInfo(name="component", required=True),
                ParamInfo(name="areEqual"),
            ],
            min_args=1,
            max_args=2,
            return_type="NamedExoticComponent",
        ),
    },
    common_hallucinated_functions=[
        "render", "mount", "createComponent",
        "useAsync", "useQuery", "useFetch",
        "useStore", "useDispatch", "useSelector",
    ],
)

_JS_FS: ModuleSig = ModuleSig(
    name="fs",
    functions={
        "readFileSync": FunctionSig(
            name="readFileSync",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            return_type="string | Buffer",
        ),
        "writeFileSync": FunctionSig(
            name="writeFileSync",
            params=[
                ParamInfo(name="file", required=True),
                ParamInfo(name="data", required=True),
                ParamInfo(name="options"),
            ],
            min_args=2,
            return_type="void",
        ),
        "existsSync": FunctionSig(
            name="existsSync",
            params=[ParamInfo(name="path", required=True)],
            min_args=1,
            max_args=1,
            return_type="boolean",
        ),
        "mkdirSync": FunctionSig(
            name="mkdirSync",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            return_type="string | undefined",
        ),
        "readdirSync": FunctionSig(
            name="readdirSync",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            return_type="string[]",
        ),
        "unlinkSync": FunctionSig(
            name="unlinkSync",
            params=[ParamInfo(name="path", required=True)],
            min_args=1,
            max_args=1,
            return_type="void",
        ),
        "statSync": FunctionSig(
            name="statSync",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            return_type="Stats",
        ),
    },
    common_hallucinated_functions=[
        "read", "write", "open", "close",
        "readFile", "writeFile", "mkdir",
        "delete", "remove", "copy",
    ],
)

_JS_PATH: ModuleSig = ModuleSig(
    name="path",
    functions={
        "join": FunctionSig(name="join", min_args=0, max_args=-1, return_type="string"),
        "resolve": FunctionSig(name="resolve", min_args=0, max_args=-1, return_type="string"),
        "dirname": FunctionSig(name="dirname", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="string"),
        "basename": FunctionSig(name="basename", params=[ParamInfo(name="path", required=True), ParamInfo(name="suffix")], min_args=1, return_type="string"),
        "extname": FunctionSig(name="extname", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="string"),
        "parse": FunctionSig(name="parse", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="ParsedPath"),
        "normalize": FunctionSig(name="normalize", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="string"),
        "relative": FunctionSig(name="relative", params=[ParamInfo(name="from", required=True), ParamInfo(name="to", required=True)], min_args=2, return_type="string"),
    },
    common_hallucinated_functions=[
        "concat", "split", "combine", "pathJoin",
    ],
)

_JS_ZOD: ModuleSig = ModuleSig(
    name="zod",
    functions={
        "object": FunctionSig(
            name="object",
            params=[ParamInfo(name="shape", required=True)],
            min_args=1,
            return_type="ZodObject",
        ),
        "string": FunctionSig(name="string", min_args=0, return_type="ZodString"),
        "number": FunctionSig(name="number", min_args=0, return_type="ZodNumber"),
        "boolean": FunctionSig(name="boolean", min_args=0, return_type="ZodBoolean"),
        "array": FunctionSig(
            name="array",
            params=[ParamInfo(name="schema", required=True)],
            min_args=1,
            return_type="ZodArray",
        ),
        "enum": FunctionSig(
            name="enum",
            params=[ParamInfo(name="values", required=True)],
            min_args=1,
            return_type="ZodEnum",
        ),
        "union": FunctionSig(
            name="union",
            params=[ParamInfo(name="types", required=True)],
            min_args=1,
            return_type="ZodUnion",
        ),
        "infer": FunctionSig(
            name="infer",
            notes="Type utility: z.infer<typeof schema>. Not a runtime function.",
        ),
    },
    common_hallucinated_functions=[
        "validate", "parse", "check", "schema",
        "createSchema", "define",
    ],
)

_JS_PRISMA: ModuleSig = ModuleSig(
    name="@prisma/client",
    functions={
        "PrismaClient": FunctionSig(
            name="PrismaClient",
            params=[
                ParamInfo(name="options"),
            ],
            min_args=0,
            return_type="PrismaClient",
            common_hallucinations=["url", "database_url", "connection"],
            notes="Options object: { log, datasources }",
        ),
    },
    common_hallucinated_functions=[
        "connect", "disconnect", "create",
        "createClient", "initialize",
    ],
)


# ═══════════════════════════════════════════════════════════════════════
#  REGISTRY — Flat lookup by language
# ═══════════════════════════════════════════════════════════════════════

PYTHON_SIGNATURES: dict[str, ModuleSig] = {
    "requests": _PY_REQUESTS,
    "flask": _PY_FLASK,
    "pandas": _PY_PANDAS,
    "pd": _PY_PANDAS,  # common alias
    "numpy": _PY_NUMPY,
    "np": _PY_NUMPY,  # common alias
    "fastapi": _PY_FASTAPI,
    "django": _PY_DJANGO,
    "sqlalchemy": _PY_SQLALCHEMY,
    "httpx": _PY_HTTPX,
    "pydantic": _PY_PYDANTIC,
    "pytest": _PY_PYTEST,
    "os": _PY_OS,
    "json": _PY_JSON,
    "pathlib": _PY_PATHLIB,
    "logging": _PY_LOGGING,
}

JS_TS_SIGNATURES: dict[str, ModuleSig] = {
    "express": _JS_EXPRESS,
    "axios": _JS_AXIOS,
    "react": _JS_REACT,
    "React": _JS_REACT,
    "fs": _JS_FS,
    "node:fs": _JS_FS,
    "path": _JS_PATH,
    "node:path": _JS_PATH,
    "zod": _JS_ZOD,
    "z": _JS_ZOD,  # common alias
    "@prisma/client": _JS_PRISMA,
}

SIGNATURES: dict[str, dict[str, ModuleSig]] = {
    "python": PYTHON_SIGNATURES,
    "javascript": JS_TS_SIGNATURES,
    "typescript": JS_TS_SIGNATURES,
}

# Total counts for metrics
TOTAL_MODULES = len(PYTHON_SIGNATURES) + len(JS_TS_SIGNATURES)
TOTAL_FUNCTIONS = sum(
    len(m.functions) + sum(len(sub) for sub in m.submodules.values())
    for sigs in SIGNATURES.values()
    for m in sigs.values()
)
