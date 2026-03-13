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
        "read_table": FunctionSig(
            name="read_table",
            params=[
                ParamInfo(name="filepath_or_buffer", required=True),
                ParamInfo(name="sep"),
                ParamInfo(name="header"),
                ParamInfo(name="names"),
                ParamInfo(name="index_col"),
                ParamInfo(name="usecols"),
                ParamInfo(name="dtype"),
                ParamInfo(name="engine"),
                ParamInfo(name="nrows"),
                ParamInfo(name="skiprows"),
                ParamInfo(name="encoding"),
            ],
            min_args=1,
            return_type="DataFrame",
            notes="Reads tab-separated data. Default sep='\\t'.",
            common_hallucinations=["file", "path", "delimiter"],
        ),
    },
    common_hallucinated_functions=[
        "read", "load", "load_csv", "from_csv", "from_json",
        "create_dataframe", "from_dict_list",
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
            max_args=3,
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
            max_args=3,
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
                ParamInfo(name="shape", required=True),
                ParamInfo(name="newshape", deprecated=True, deprecated_since="2.0",
                          replacement="shape"),
                ParamInfo(name="order"),
            ],
            min_args=2,
            max_args=3,
            return_type="ndarray",
            common_hallucinations=["dims", "dimensions"],
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
            max_args=3,
            return_type="ndarray",
        ),
        "dot": FunctionSig(
            name="dot",
            params=[
                ParamInfo(name="a", required=True),
                ParamInfo(name="b", required=True),
                ParamInfo(name="out"),
            ],
            min_args=2,
            max_args=3,
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
                ParamInfo(name="future", deprecated=True, deprecated_since="2.0",
                          replacement="(default behavior in 2.0+)"),
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
        "getcwd": FunctionSig(
            name="getcwd",
            params=[],
            min_args=0,
            max_args=0,
            return_type="str",
        ),
        "walk": FunctionSig(
            name="walk",
            params=[
                ParamInfo(name="top", required=True),
                ParamInfo(name="topdown"),
                ParamInfo(name="onerror"),
                ParamInfo(name="followlinks"),
            ],
            min_args=1,
            return_type="Iterator",
        ),
        "rename": FunctionSig(
            name="rename",
            params=[
                ParamInfo(name="src", required=True),
                ParamInfo(name="dst", required=True),
            ],
            min_args=2,
            max_args=2,
            return_type="None",
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
            "normpath": FunctionSig(name="normpath", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="str"),
            "relpath": FunctionSig(name="relpath", params=[ParamInfo(name="path", required=True), ParamInfo(name="start")], min_args=1, max_args=2, return_type="str"),
            "expanduser": FunctionSig(name="expanduser", params=[ParamInfo(name="path", required=True)], min_args=1, return_type="str"),
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
        "log": FunctionSig(
            name="log",
            params=[
                ParamInfo(name="level", required=True),
                ParamInfo(name="msg", required=True),
            ],
            min_args=2,
            max_args=-1,
            return_type="None",
            notes="logging.log(level, msg, *args, **kwargs)",
        ),
    },
    common_hallucinated_functions=[
        "create_logger", "set_level",
        "add_handler", "Logger",
    ],
)

_PY_SUBPROCESS: ModuleSig = ModuleSig(
    name="subprocess",
    functions={
        "run": FunctionSig(
            name="run",
            params=[
                ParamInfo(name="args", required=True),
                ParamInfo(name="stdin"),
                ParamInfo(name="input"),
                ParamInfo(name="stdout"),
                ParamInfo(name="stderr"),
                ParamInfo(name="capture_output"),
                ParamInfo(name="shell"),
                ParamInfo(name="cwd"),
                ParamInfo(name="timeout"),
                ParamInfo(name="check"),
                ParamInfo(name="encoding"),
                ParamInfo(name="errors"),
                ParamInfo(name="text"),
                ParamInfo(name="env"),
            ],
            min_args=1,
            return_type="CompletedProcess",
            common_hallucinations=[
                "command", "cmd", "output", "wait",
                "async_", "background", "pipe",
            ],
        ),
        "Popen": FunctionSig(
            name="Popen",
            params=[
                ParamInfo(name="args", required=True),
                ParamInfo(name="bufsize"),
                ParamInfo(name="executable"),
                ParamInfo(name="stdin"),
                ParamInfo(name="stdout"),
                ParamInfo(name="stderr"),
                ParamInfo(name="shell"),
                ParamInfo(name="cwd"),
                ParamInfo(name="env"),
                ParamInfo(name="text"),
                ParamInfo(name="encoding"),
            ],
            min_args=1,
            return_type="Popen",
            common_hallucinations=["command", "cmd", "wait", "async_"],
        ),
        "call": FunctionSig(
            name="call",
            params=[
                ParamInfo(name="args", required=True),
                ParamInfo(name="stdin"),
                ParamInfo(name="stdout"),
                ParamInfo(name="stderr"),
                ParamInfo(name="shell"),
                ParamInfo(name="cwd"),
                ParamInfo(name="timeout"),
            ],
            min_args=1,
            return_type="int",
            notes="Returns returncode. Prefer subprocess.run with check=True.",
        ),
        "check_output": FunctionSig(
            name="check_output",
            params=[
                ParamInfo(name="args", required=True),
                ParamInfo(name="stdin"),
                ParamInfo(name="stderr"),
                ParamInfo(name="shell"),
                ParamInfo(name="cwd"),
                ParamInfo(name="timeout"),
                ParamInfo(name="encoding"),
                ParamInfo(name="text"),
            ],
            min_args=1,
            return_type="bytes | str",
            common_hallucinations=["output", "capture", "stdout"],
        ),
        "check_call": FunctionSig(
            name="check_call",
            params=[
                ParamInfo(name="args", required=True),
                ParamInfo(name="stdin"),
                ParamInfo(name="stdout"),
                ParamInfo(name="stderr"),
                ParamInfo(name="shell"),
                ParamInfo(name="cwd"),
                ParamInfo(name="timeout"),
            ],
            min_args=1,
            return_type="int",
        ),
    },
    common_hallucinated_functions=[
        "execute", "exec", "system", "command",
        "run_command", "shell", "spawn",
    ],
)

_PY_RE: ModuleSig = ModuleSig(
    name="re",
    functions={
        "compile": FunctionSig(
            name="compile",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=1,
            max_args=2,
            return_type="Pattern",
            common_hallucinations=["regex", "options", "mode"],
        ),
        "match": FunctionSig(
            name="match",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=3,
            return_type="Match | None",
            common_hallucinations=["text", "input", "regex"],
        ),
        "search": FunctionSig(
            name="search",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=3,
            return_type="Match | None",
        ),
        "findall": FunctionSig(
            name="findall",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=3,
            return_type="list[str]",
            common_hallucinations=["text", "input", "count", "limit"],
        ),
        "finditer": FunctionSig(
            name="finditer",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=3,
            return_type="Iterator[Match]",
        ),
        "sub": FunctionSig(
            name="sub",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="repl", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="count"),
                ParamInfo(name="flags"),
            ],
            min_args=3,
            max_args=5,
            return_type="str",
            common_hallucinations=["replacement", "replace", "limit", "text"],
        ),
        "split": FunctionSig(
            name="split",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="maxsplit"),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=4,
            return_type="list[str]",
        ),
        "fullmatch": FunctionSig(
            name="fullmatch",
            params=[
                ParamInfo(name="pattern", required=True),
                ParamInfo(name="string", required=True),
                ParamInfo(name="flags"),
            ],
            min_args=2,
            max_args=3,
            return_type="Match | None",
        ),
        "escape": FunctionSig(
            name="escape",
            params=[ParamInfo(name="pattern", required=True)],
            min_args=1,
            max_args=1,
            return_type="str",
        ),
    },
    common_hallucinated_functions=[
        "find", "replace", "test", "exec",
        "match_all", "grep", "extract",
    ],
)

_PY_DATETIME: ModuleSig = ModuleSig(
    name="datetime",
    functions={
        "datetime": FunctionSig(
            name="datetime",
            params=[
                ParamInfo(name="year", required=True),
                ParamInfo(name="month", required=True),
                ParamInfo(name="day", required=True),
                ParamInfo(name="hour"),
                ParamInfo(name="minute"),
                ParamInfo(name="second"),
                ParamInfo(name="microsecond"),
                ParamInfo(name="tzinfo"),
            ],
            min_args=3,
            return_type="datetime",
            common_hallucinations=["date", "time", "timestamp", "format"],
            notes="Constructor: datetime.datetime(year, month, day, ...)",
        ),
        "date": FunctionSig(
            name="date",
            params=[
                ParamInfo(name="year", required=True),
                ParamInfo(name="month", required=True),
                ParamInfo(name="day", required=True),
            ],
            min_args=3,
            max_args=3,
            return_type="date",
        ),
        "time": FunctionSig(
            name="time",
            params=[
                ParamInfo(name="hour"),
                ParamInfo(name="minute"),
                ParamInfo(name="second"),
                ParamInfo(name="microsecond"),
                ParamInfo(name="tzinfo"),
            ],
            min_args=0,
            return_type="time",
        ),
        "timedelta": FunctionSig(
            name="timedelta",
            params=[
                ParamInfo(name="days"),
                ParamInfo(name="seconds"),
                ParamInfo(name="microseconds"),
                ParamInfo(name="milliseconds"),
                ParamInfo(name="minutes"),
                ParamInfo(name="hours"),
                ParamInfo(name="weeks"),
            ],
            min_args=0,
            return_type="timedelta",
            common_hallucinations=["months", "years", "duration"],
            notes="No 'months' or 'years' — use dateutil.relativedelta.",
        ),
        "timezone": FunctionSig(
            name="timezone",
            params=[
                ParamInfo(name="offset", required=True),
                ParamInfo(name="name"),
            ],
            min_args=1,
            max_args=2,
            return_type="timezone",
        ),
        # Class methods on datetime.datetime — commonly accessed via
        # ``from datetime import datetime; datetime.now()``
        "now": FunctionSig(
            name="now",
            params=[ParamInfo(name="tz")],
            min_args=0,
            max_args=1,
            return_type="datetime",
            notes="Class method: datetime.datetime.now(tz=None).",
        ),
        "today": FunctionSig(
            name="today",
            params=[],
            min_args=0,
            max_args=0,
            return_type="datetime",
            notes="Class method: datetime.datetime.today(). Consider now() instead.",
        ),
        "utcnow": FunctionSig(
            name="utcnow",
            params=[],
            min_args=0,
            max_args=0,
            return_type="datetime",
            deprecated=True,
            deprecated_since="3.12",
            replacement="datetime.now(tz=timezone.utc)",
            notes="Returns naive UTC datetime. Use now(tz=timezone.utc) instead.",
        ),
        "strptime": FunctionSig(
            name="strptime",
            params=[
                ParamInfo(name="date_string", required=True),
                ParamInfo(name="format", required=True),
            ],
            min_args=2,
            max_args=2,
            return_type="datetime",
            notes="Class method: datetime.datetime.strptime(date_string, format).",
        ),
        "fromtimestamp": FunctionSig(
            name="fromtimestamp",
            params=[
                ParamInfo(name="timestamp", required=True),
                ParamInfo(name="tz"),
            ],
            min_args=1,
            max_args=2,
            return_type="datetime",
        ),
        "fromisoformat": FunctionSig(
            name="fromisoformat",
            params=[
                ParamInfo(name="date_string", required=True),
            ],
            min_args=1,
            max_args=1,
            return_type="datetime",
        ),
        "combine": FunctionSig(
            name="combine",
            params=[
                ParamInfo(name="date", required=True),
                ParamInfo(name="time", required=True),
                ParamInfo(name="tzinfo"),
            ],
            min_args=2,
            max_args=3,
            return_type="datetime",
        ),
        "strftime": FunctionSig(
            name="strftime",
            params=[
                ParamInfo(name="format", required=True),
            ],
            min_args=1,
            max_args=1,
            return_type="str",
            notes="Instance method also callable as datetime.strftime(dt, fmt).",
        ),
    },
    common_hallucinated_functions=[
        "parse", "from_timestamp", "from_string",
    ],
)

_PY_HASHLIB: ModuleSig = ModuleSig(
    name="hashlib",
    functions={
        "md5": FunctionSig(
            name="md5",
            params=[
                ParamInfo(name="data"),
                ParamInfo(name="usedforsecurity"),
            ],
            min_args=0,
            max_args=2,
            return_type="HASH",
            common_hallucinations=["string", "encoding", "text"],
        ),
        "sha256": FunctionSig(
            name="sha256",
            params=[
                ParamInfo(name="data"),
                ParamInfo(name="usedforsecurity"),
            ],
            min_args=0,
            max_args=2,
            return_type="HASH",
            common_hallucinations=["string", "text", "message"],
        ),
        "sha1": FunctionSig(
            name="sha1",
            params=[
                ParamInfo(name="data"),
                ParamInfo(name="usedforsecurity"),
            ],
            min_args=0,
            max_args=2,
            return_type="HASH",
        ),
        "sha512": FunctionSig(
            name="sha512",
            params=[
                ParamInfo(name="data"),
                ParamInfo(name="usedforsecurity"),
            ],
            min_args=0,
            max_args=2,
            return_type="HASH",
        ),
        "new": FunctionSig(
            name="new",
            params=[
                ParamInfo(name="name", required=True),
                ParamInfo(name="data"),
                ParamInfo(name="usedforsecurity"),
            ],
            min_args=1,
            max_args=3,
            return_type="HASH",
            common_hallucinations=["algorithm", "algo", "hash_type"],
        ),
        "pbkdf2_hmac": FunctionSig(
            name="pbkdf2_hmac",
            params=[
                ParamInfo(name="hash_name", required=True),
                ParamInfo(name="password", required=True),
                ParamInfo(name="salt", required=True),
                ParamInfo(name="iterations", required=True),
                ParamInfo(name="dklen"),
            ],
            min_args=4,
            max_args=5,
            return_type="bytes",
            common_hallucinations=["rounds", "key_length", "algo"],
        ),
    },
    common_hallucinated_functions=[
        "hash", "digest", "hexdigest", "create_hash",
        "hmac", "sha", "encrypt",
    ],
)

_PY_COLLECTIONS: ModuleSig = ModuleSig(
    name="collections",
    functions={
        "Counter": FunctionSig(
            name="Counter",
            params=[ParamInfo(name="iterable")],
            min_args=0,
            return_type="Counter",
            common_hallucinations=["data", "elements", "items", "list"],
        ),
        "defaultdict": FunctionSig(
            name="defaultdict",
            params=[ParamInfo(name="default_factory")],
            min_args=0,
            max_args=-1,
            return_type="defaultdict",
            common_hallucinations=["type", "default", "factory"],
        ),
        "OrderedDict": FunctionSig(
            name="OrderedDict",
            min_args=0,
            max_args=-1,
            return_type="OrderedDict",
        ),
        "namedtuple": FunctionSig(
            name="namedtuple",
            params=[
                ParamInfo(name="typename", required=True),
                ParamInfo(name="field_names", required=True),
                ParamInfo(name="rename"),
                ParamInfo(name="defaults"),
                ParamInfo(name="module"),
            ],
            min_args=2,
            max_args=5,
            return_type="type",
            common_hallucinations=["name", "fields", "class_name"],
        ),
        "deque": FunctionSig(
            name="deque",
            params=[
                ParamInfo(name="iterable"),
                ParamInfo(name="maxlen"),
            ],
            min_args=0,
            max_args=2,
            return_type="deque",
            common_hallucinations=["size", "capacity", "max_size"],
        ),
        "ChainMap": FunctionSig(
            name="ChainMap",
            min_args=0,
            max_args=-1,
            return_type="ChainMap",
        ),
    },
    common_hallucinated_functions=[
        "Dict", "List", "Set", "Tuple",
        "SortedDict", "SortedList", "FrozenDict",
    ],
)

_PY_OPENAI: ModuleSig = ModuleSig(
    name="openai",
    functions={
        "OpenAI": FunctionSig(
            name="OpenAI",
            params=[
                ParamInfo(name="api_key"),
                ParamInfo(name="organization"),
                ParamInfo(name="project"),
                ParamInfo(name="base_url"),
                ParamInfo(name="timeout"),
                ParamInfo(name="max_retries"),
                ParamInfo(name="default_headers"),
                ParamInfo(name="default_query"),
                ParamInfo(name="http_client"),
            ],
            min_args=0,
            return_type="OpenAI",
            common_hallucinations=[
                "model", "key", "token", "engine",
                "api_base", "api_version",
            ],
            notes="api_base/api_version are v0.x params. Use base_url in v1+.",
        ),
        "AsyncOpenAI": FunctionSig(
            name="AsyncOpenAI",
            params=[
                ParamInfo(name="api_key"),
                ParamInfo(name="organization"),
                ParamInfo(name="project"),
                ParamInfo(name="base_url"),
                ParamInfo(name="timeout"),
                ParamInfo(name="max_retries"),
                ParamInfo(name="default_headers"),
                ParamInfo(name="http_client"),
            ],
            min_args=0,
            return_type="AsyncOpenAI",
            common_hallucinations=["model", "key", "engine", "api_base"],
        ),
    },
    common_hallucinated_functions=[
        "Completion", "ChatCompletion", "create",
        "complete", "chat", "generate",
        "Embedding", "Image", "Audio",
    ],
)

_PY_ASYNCIO: ModuleSig = ModuleSig(
    name="asyncio",
    functions={
        "run": FunctionSig(
            name="run",
            params=[
                ParamInfo(name="main", required=True),
                ParamInfo(name="debug"),
            ],
            min_args=1,
            max_args=2,
            return_type="T",
            common_hallucinations=["loop", "coro", "coroutine"],
        ),
        "create_task": FunctionSig(
            name="create_task",
            params=[
                ParamInfo(name="coro", required=True),
                ParamInfo(name="name"),
            ],
            min_args=1,
            max_args=2,
            return_type="Task",
            common_hallucinations=["callback", "func", "function"],
        ),
        "gather": FunctionSig(
            name="gather",
            min_args=0,
            max_args=-1,
            return_type="Future",
            common_hallucinations=["tasks", "coroutines", "coros"],
            notes="Takes *aws positional args, not a list.",
        ),
        "sleep": FunctionSig(
            name="sleep",
            params=[
                ParamInfo(name="delay", required=True),
                ParamInfo(name="result"),
            ],
            min_args=1,
            max_args=2,
            return_type="Coroutine",
        ),
        "wait": FunctionSig(
            name="wait",
            params=[
                ParamInfo(name="fs", required=True),
                ParamInfo(name="timeout"),
                ParamInfo(name="return_when"),
            ],
            min_args=1,
            max_args=3,
            return_type="tuple[set, set]",
        ),
        "wait_for": FunctionSig(
            name="wait_for",
            params=[
                ParamInfo(name="fut", required=True),
                ParamInfo(name="timeout", required=True),
            ],
            min_args=2,
            max_args=2,
            return_type="T",
        ),
        "get_event_loop": FunctionSig(
            name="get_event_loop",
            min_args=0,
            max_args=0,
            return_type="AbstractEventLoop",
            deprecated=True,
            deprecated_since="3.10",
            replacement="asyncio.run() or asyncio.get_running_loop()",
        ),
        "get_running_loop": FunctionSig(
            name="get_running_loop",
            min_args=0,
            max_args=0,
            return_type="AbstractEventLoop",
        ),
        "Queue": FunctionSig(
            name="Queue",
            params=[ParamInfo(name="maxsize")],
            min_args=0,
            max_args=1,
            return_type="Queue",
        ),
        "Semaphore": FunctionSig(
            name="Semaphore",
            params=[ParamInfo(name="value")],
            min_args=0,
            max_args=1,
            return_type="Semaphore",
        ),
        "Lock": FunctionSig(
            name="Lock",
            min_args=0,
            max_args=0,
            return_type="Lock",
        ),
        "Event": FunctionSig(
            name="Event",
            min_args=0,
            max_args=0,
            return_type="Event",
        ),
    },
    common_hallucinated_functions=[
        "async_run", "start", "spawn",
        "parallel", "concurrent", "execute",
        "create_loop", "new_event_loop",
    ],
)

_PY_SYS: ModuleSig = ModuleSig(
    name="sys",
    functions={
        "exit": FunctionSig(
            name="exit",
            params=[ParamInfo(name="arg")],
            min_args=0,
            max_args=1,
            return_type="NoReturn",
            common_hallucinations=["code", "status", "message"],
        ),
        "getsizeof": FunctionSig(
            name="getsizeof",
            params=[
                ParamInfo(name="object", required=True),
                ParamInfo(name="default"),
            ],
            min_args=1,
            max_args=2,
            return_type="int",
        ),
        "getrecursionlimit": FunctionSig(
            name="getrecursionlimit",
            min_args=0,
            max_args=0,
            return_type="int",
        ),
        "setrecursionlimit": FunctionSig(
            name="setrecursionlimit",
            params=[ParamInfo(name="limit", required=True)],
            min_args=1,
            max_args=1,
            return_type="None",
        ),
    },
    common_hallucinated_functions=[
        "args", "print", "input", "os",
        "getenv", "platform_info",
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
        "useStore",
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
            max_args=2,
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
            max_args=3,
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
            max_args=2,
            return_type="string | undefined",
        ),
        "readdirSync": FunctionSig(
            name="readdirSync",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=2,
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
            max_args=2,
            return_type="Stats",
        ),
        "readFile": FunctionSig(
            name="readFile",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=2,
            return_type="void",
            notes="Async callback variant. Use readFileSync for sync or fs/promises for async/await.",
        ),
        "writeFile": FunctionSig(
            name="writeFile",
            params=[
                ParamInfo(name="file", required=True),
                ParamInfo(name="data", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=3,
            return_type="void",
            notes="Async callback variant.",
        ),
        "mkdir": FunctionSig(
            name="mkdir",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=2,
            return_type="void",
            notes="Async callback variant. Use mkdirSync for sync.",
        ),
        "open": FunctionSig(
            name="open",
            params=[
                ParamInfo(name="path", required=True),
                ParamInfo(name="flags", required=True),
                ParamInfo(name="mode"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=3,
            return_type="void",
        ),
        "close": FunctionSig(
            name="close",
            params=[
                ParamInfo(name="fd", required=True),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            return_type="void",
        ),
        "read": FunctionSig(
            name="read",
            params=[
                ParamInfo(name="fd", required=True),
                ParamInfo(name="buffer", required=True),
                ParamInfo(name="offset", required=True),
                ParamInfo(name="length", required=True),
                ParamInfo(name="position"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=5,
            return_type="void",
        ),
        "write": FunctionSig(
            name="write",
            params=[
                ParamInfo(name="fd", required=True),
                ParamInfo(name="buffer", required=True),
                ParamInfo(name="offset"),
                ParamInfo(name="length"),
                ParamInfo(name="position"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=2,
            return_type="void",
        ),
    },
    common_hallucinated_functions=[
        "delete", "remove", "copy", "move",
        "readdir", "isFile", "isDirectory",
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

_JS_CRYPTO: ModuleSig = ModuleSig(
    name="crypto",
    functions={
        "createHash": FunctionSig(
            name="createHash",
            params=[
                ParamInfo(name="algorithm", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=2,
            return_type="Hash",
            common_hallucinations=["type", "algo", "hashType"],
        ),
        "createHmac": FunctionSig(
            name="createHmac",
            params=[
                ParamInfo(name="algorithm", required=True),
                ParamInfo(name="key", required=True),
                ParamInfo(name="options"),
            ],
            min_args=2,
            max_args=3,
            return_type="Hmac",
        ),
        "createCipheriv": FunctionSig(
            name="createCipheriv",
            params=[
                ParamInfo(name="algorithm", required=True),
                ParamInfo(name="key", required=True),
                ParamInfo(name="iv", required=True),
                ParamInfo(name="options"),
            ],
            min_args=3,
            max_args=4,
            return_type="Cipher",
            common_hallucinations=["cipher", "mode", "padding"],
        ),
        "createDecipheriv": FunctionSig(
            name="createDecipheriv",
            params=[
                ParamInfo(name="algorithm", required=True),
                ParamInfo(name="key", required=True),
                ParamInfo(name="iv", required=True),
                ParamInfo(name="options"),
            ],
            min_args=3,
            max_args=4,
            return_type="Decipher",
        ),
        "randomBytes": FunctionSig(
            name="randomBytes",
            params=[
                ParamInfo(name="size", required=True),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            max_args=2,
            return_type="Buffer",
            common_hallucinations=["length", "count", "bytes"],
        ),
        "randomUUID": FunctionSig(
            name="randomUUID",
            params=[ParamInfo(name="options")],
            min_args=0,
            max_args=1,
            return_type="string",
        ),
        "pbkdf2": FunctionSig(
            name="pbkdf2",
            params=[
                ParamInfo(name="password", required=True),
                ParamInfo(name="salt", required=True),
                ParamInfo(name="iterations", required=True),
                ParamInfo(name="keylen", required=True),
                ParamInfo(name="digest", required=True),
                ParamInfo(name="callback", required=True),
            ],
            min_args=6,
            max_args=6,
            return_type="void",
        ),
        "scrypt": FunctionSig(
            name="scrypt",
            params=[
                ParamInfo(name="password", required=True),
                ParamInfo(name="salt", required=True),
                ParamInfo(name="keylen", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback", required=True),
            ],
            min_args=4,
            max_args=5,
            return_type="void",
        ),
    },
    common_hallucinated_functions=[
        "encrypt", "decrypt", "hash", "sha256",
        "md5", "generateKey", "sign", "verify",
    ],
)

_JS_HTTP: ModuleSig = ModuleSig(
    name="http",
    functions={
        "createServer": FunctionSig(
            name="createServer",
            params=[
                ParamInfo(name="options"),
                ParamInfo(name="requestListener"),
            ],
            min_args=0,
            max_args=2,
            return_type="Server",
            common_hallucinations=["callback", "handler", "port"],
        ),
        "request": FunctionSig(
            name="request",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            max_args=3,
            return_type="ClientRequest",
            common_hallucinations=["method", "headers", "body"],
        ),
        "get": FunctionSig(
            name="get",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            max_args=3,
            return_type="ClientRequest",
        ),
    },
    common_hallucinated_functions=[
        "listen", "fetch", "post", "put",
        "delete", "send", "connect",
    ],
)

_JS_CHILD_PROCESS: ModuleSig = ModuleSig(
    name="child_process",
    functions={
        "exec": FunctionSig(
            name="exec",
            params=[
                ParamInfo(name="command", required=True),
                ParamInfo(name="options"),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            max_args=3,
            return_type="ChildProcess",
            common_hallucinations=["cmd", "args", "shell"],
        ),
        "execFile": FunctionSig(
            name="execFile",
            params=[
                ParamInfo(name="file", required=True),
                ParamInfo(name="args"),
                ParamInfo(name="options"),
                ParamInfo(name="callback"),
            ],
            min_args=1,
            max_args=4,
            return_type="ChildProcess",
        ),
        "spawn": FunctionSig(
            name="spawn",
            params=[
                ParamInfo(name="command", required=True),
                ParamInfo(name="args"),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=3,
            return_type="ChildProcess",
            common_hallucinations=["cmd", "params", "env"],
        ),
        "fork": FunctionSig(
            name="fork",
            params=[
                ParamInfo(name="modulePath", required=True),
                ParamInfo(name="args"),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=3,
            return_type="ChildProcess",
            common_hallucinations=["script", "file", "path"],
        ),
        "execSync": FunctionSig(
            name="execSync",
            params=[
                ParamInfo(name="command", required=True),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=2,
            return_type="Buffer | string",
        ),
        "spawnSync": FunctionSig(
            name="spawnSync",
            params=[
                ParamInfo(name="command", required=True),
                ParamInfo(name="args"),
                ParamInfo(name="options"),
            ],
            min_args=1,
            max_args=3,
            return_type="SpawnSyncReturns",
        ),
    },
    common_hallucinated_functions=[
        "run", "execute", "system", "command",
        "shell", "process", "start",
    ],
)

_JS_NEXT: ModuleSig = ModuleSig(
    name="next/navigation",
    functions={
        "useRouter": FunctionSig(
            name="useRouter",
            min_args=0,
            max_args=0,
            return_type="AppRouterInstance",
            common_hallucinations=["options", "config"],
            notes="App Router hook. Pages Router: import from 'next/router'.",
        ),
        "usePathname": FunctionSig(
            name="usePathname",
            min_args=0,
            max_args=0,
            return_type="string",
        ),
        "useSearchParams": FunctionSig(
            name="useSearchParams",
            min_args=0,
            max_args=0,
            return_type="ReadonlyURLSearchParams",
        ),
        "useParams": FunctionSig(
            name="useParams",
            min_args=0,
            max_args=0,
            return_type="Params",
        ),
        "redirect": FunctionSig(
            name="redirect",
            params=[
                ParamInfo(name="url", required=True),
                ParamInfo(name="type"),
            ],
            min_args=1,
            max_args=2,
            return_type="never",
            common_hallucinations=["path", "permanent", "status"],
        ),
        "notFound": FunctionSig(
            name="notFound",
            min_args=0,
            max_args=0,
            return_type="never",
        ),
    },
    common_hallucinated_functions=[
        "navigate", "push", "replace",
        "getRouter", "getPathname", "Link",
    ],
)

_PY_MATH: ModuleSig = ModuleSig(
    name="math",
    functions={
        "ceil": FunctionSig(name="ceil", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="int"),
        "floor": FunctionSig(name="floor", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="int"),
        "sqrt": FunctionSig(name="sqrt", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "pow": FunctionSig(name="pow", params=[ParamInfo(name="x", required=True), ParamInfo(name="y", required=True)], min_args=2, max_args=2, return_type="float"),
        "sin": FunctionSig(name="sin", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "cos": FunctionSig(name="cos", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "tan": FunctionSig(name="tan", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "log": FunctionSig(name="log", params=[ParamInfo(name="x", required=True), ParamInfo(name="base")], min_args=1, max_args=2, return_type="float"),
        "log10": FunctionSig(name="log10", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "exp": FunctionSig(name="exp", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "fabs": FunctionSig(name="fabs", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="float"),
        "isfinite": FunctionSig(name="isfinite", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="bool"),
        "isnan": FunctionSig(name="isnan", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="bool"),
        "isinf": FunctionSig(name="isinf", params=[ParamInfo(name="x", required=True)], min_args=1, max_args=1, return_type="bool"),
    },
    common_hallucinated_functions=["random_int", "sum", "average", "between"],
)

_PY_STATISTICS: ModuleSig = ModuleSig(
    name="statistics",
    functions={
        "mean": FunctionSig(name="mean", params=[ParamInfo(name="data", required=True)], min_args=1, max_args=1, return_type="float"),
        "fmean": FunctionSig(name="fmean", params=[ParamInfo(name="data", required=True)], min_args=1, max_args=1, return_type="float"),
        "median": FunctionSig(name="median", params=[ParamInfo(name="data", required=True)], min_args=1, max_args=1, return_type="float"),
        "mode": FunctionSig(name="mode", params=[ParamInfo(name="data", required=True)], min_args=1, max_args=1, return_type="object"),
        "multimode": FunctionSig(name="multimode", params=[ParamInfo(name="data", required=True)], min_args=1, max_args=1, return_type="list[object]"),
        "stdev": FunctionSig(name="stdev", params=[ParamInfo(name="data", required=True), ParamInfo(name="xbar")], min_args=1, max_args=2, return_type="float"),
        "variance": FunctionSig(name="variance", params=[ParamInfo(name="data", required=True), ParamInfo(name="xbar")], min_args=1, max_args=2, return_type="float"),
        "pstdev": FunctionSig(name="pstdev", params=[ParamInfo(name="data", required=True), ParamInfo(name="mu")], min_args=1, max_args=2, return_type="float"),
        "pvariance": FunctionSig(name="pvariance", params=[ParamInfo(name="data", required=True), ParamInfo(name="mu")], min_args=1, max_args=2, return_type="float"),
        "quantiles": FunctionSig(name="quantiles", params=[ParamInfo(name="data", required=True), ParamInfo(name="n"), ParamInfo(name="method")], min_args=1, max_args=3, return_type="list[float]"),
    },
    common_hallucinated_functions=["average", "stddev", "percentile", "sum"],
)

_PY_UUID: ModuleSig = ModuleSig(
    name="uuid",
    functions={
        "UUID": FunctionSig(name="UUID", params=[ParamInfo(name="hex")], min_args=0, max_args=-1, return_type="UUID"),
        "uuid1": FunctionSig(name="uuid1", params=[ParamInfo(name="node"), ParamInfo(name="clock_seq")], min_args=0, max_args=2, return_type="UUID"),
        "uuid3": FunctionSig(name="uuid3", params=[ParamInfo(name="namespace", required=True), ParamInfo(name="name", required=True)], min_args=2, max_args=2, return_type="UUID"),
        "uuid4": FunctionSig(name="uuid4", min_args=0, max_args=0, return_type="UUID"),
        "uuid5": FunctionSig(name="uuid5", params=[ParamInfo(name="namespace", required=True), ParamInfo(name="name", required=True)], min_args=2, max_args=2, return_type="UUID"),
        "getnode": FunctionSig(name="getnode", min_args=0, max_args=0, return_type="int"),
    },
    common_hallucinated_functions=["new", "generate", "random", "short"],
)

_PY_SHUTIL: ModuleSig = ModuleSig(
    name="shutil",
    functions={
        "copy": FunctionSig(name="copy", params=[ParamInfo(name="src", required=True), ParamInfo(name="dst", required=True), ParamInfo(name="follow_symlinks")], min_args=2, max_args=3, return_type="str"),
        "copy2": FunctionSig(name="copy2", params=[ParamInfo(name="src", required=True), ParamInfo(name="dst", required=True), ParamInfo(name="follow_symlinks")], min_args=2, max_args=3, return_type="str"),
        "copyfile": FunctionSig(name="copyfile", params=[ParamInfo(name="src", required=True), ParamInfo(name="dst", required=True), ParamInfo(name="follow_symlinks")], min_args=2, max_args=3, return_type="str"),
        "move": FunctionSig(name="move", params=[ParamInfo(name="src", required=True), ParamInfo(name="dst", required=True), ParamInfo(name="copy_function")], min_args=2, max_args=3, return_type="str"),
        "rmtree": FunctionSig(name="rmtree", params=[ParamInfo(name="path", required=True), ParamInfo(name="ignore_errors"), ParamInfo(name="onerror")], min_args=1, max_args=3, return_type="None"),
        "which": FunctionSig(name="which", params=[ParamInfo(name="cmd", required=True), ParamInfo(name="mode"), ParamInfo(name="path")], min_args=1, max_args=3, return_type="str | None"),
        "make_archive": FunctionSig(name="make_archive", params=[ParamInfo(name="base_name", required=True), ParamInfo(name="format", required=True), ParamInfo(name="root_dir"), ParamInfo(name="base_dir")], min_args=2, max_args=-1, return_type="str"),
        "unpack_archive": FunctionSig(name="unpack_archive", params=[ParamInfo(name="filename", required=True), ParamInfo(name="extract_dir"), ParamInfo(name="format")], min_args=1, max_args=3, return_type="None"),
        "disk_usage": FunctionSig(name="disk_usage", params=[ParamInfo(name="path", required=True)], min_args=1, max_args=1, return_type="usage"),
        "chown": FunctionSig(name="chown", params=[ParamInfo(name="path", required=True), ParamInfo(name="user"), ParamInfo(name="group")], min_args=1, max_args=3, return_type="None"),
    },
    common_hallucinated_functions=["cp", "mv", "rm", "mkdir"],
)

_PY_TEMPFILE: ModuleSig = ModuleSig(
    name="tempfile",
    functions={
        "TemporaryFile": FunctionSig(name="TemporaryFile", min_args=0, max_args=-1, return_type="IO"),
        "NamedTemporaryFile": FunctionSig(name="NamedTemporaryFile", min_args=0, max_args=-1, return_type="IO"),
        "SpooledTemporaryFile": FunctionSig(name="SpooledTemporaryFile", min_args=0, max_args=-1, return_type="IO"),
        "TemporaryDirectory": FunctionSig(name="TemporaryDirectory", min_args=0, max_args=-1, return_type="TemporaryDirectory"),
        "mkdtemp": FunctionSig(name="mkdtemp", min_args=0, max_args=-1, return_type="str"),
        "mkstemp": FunctionSig(name="mkstemp", min_args=0, max_args=-1, return_type="tuple[int, str]"),
        "gettempdir": FunctionSig(name="gettempdir", min_args=0, max_args=0, return_type="str"),
        "gettempdirb": FunctionSig(name="gettempdirb", min_args=0, max_args=0, return_type="bytes"),
    },
    common_hallucinated_functions=["create_temp", "temp_path", "random_file", "cleanup"],
)

_PY_CSV: ModuleSig = ModuleSig(
    name="csv",
    functions={
        "reader": FunctionSig(name="reader", params=[ParamInfo(name="csvfile", required=True)], min_args=1, max_args=-1, return_type="reader"),
        "writer": FunctionSig(name="writer", params=[ParamInfo(name="csvfile", required=True)], min_args=1, max_args=-1, return_type="writer"),
        "DictReader": FunctionSig(name="DictReader", params=[ParamInfo(name="f", required=True), ParamInfo(name="fieldnames")], min_args=1, max_args=-1, return_type="DictReader"),
        "DictWriter": FunctionSig(name="DictWriter", params=[ParamInfo(name="f", required=True), ParamInfo(name="fieldnames", required=True)], min_args=2, max_args=-1, return_type="DictWriter"),
        "register_dialect": FunctionSig(name="register_dialect", params=[ParamInfo(name="name", required=True)], min_args=1, max_args=-1, return_type="None"),
        "get_dialect": FunctionSig(name="get_dialect", params=[ParamInfo(name="name", required=True)], min_args=1, max_args=1, return_type="Dialect"),
        "list_dialects": FunctionSig(name="list_dialects", min_args=0, max_args=0, return_type="list[str]"),
        "Sniffer": FunctionSig(name="Sniffer", min_args=0, max_args=0, return_type="Sniffer"),
    },
    common_hallucinated_functions=["parse", "to_csv", "from_csv", "write_header"],
)

_PY_SQLITE3: ModuleSig = ModuleSig(
    name="sqlite3",
    functions={
        "connect": FunctionSig(name="connect", params=[ParamInfo(name="database", required=True), ParamInfo(name="timeout"), ParamInfo(name="detect_types"), ParamInfo(name="isolation_level"), ParamInfo(name="check_same_thread"), ParamInfo(name="factory"), ParamInfo(name="cached_statements"), ParamInfo(name="uri")], min_args=1, max_args=8, return_type="Connection"),
        "Row": FunctionSig(name="Row", min_args=0, max_args=0, return_type="Row"),
        "register_adapter": FunctionSig(name="register_adapter", params=[ParamInfo(name="type", required=True), ParamInfo(name="adapter", required=True)], min_args=2, max_args=2, return_type="None"),
        "register_converter": FunctionSig(name="register_converter", params=[ParamInfo(name="typename", required=True), ParamInfo(name="converter", required=True)], min_args=2, max_args=2, return_type="None"),
        "enable_callback_tracebacks": FunctionSig(name="enable_callback_tracebacks", params=[ParamInfo(name="flag", required=True)], min_args=1, max_args=1, return_type="None"),
        "complete_statement": FunctionSig(name="complete_statement", params=[ParamInfo(name="statement", required=True)], min_args=1, max_args=1, return_type="bool"),
        "sqlite_version": FunctionSig(name="sqlite_version", min_args=0, max_args=0, return_type="str"),
        "version": FunctionSig(name="version", min_args=0, max_args=0, return_type="str"),
    },
    common_hallucinated_functions=["open", "execute", "query", "transaction"],
)

_PY_URLLIB_PARSE: ModuleSig = ModuleSig(
    name="urllib.parse",
    functions={
        "urlparse": FunctionSig(name="urlparse", params=[ParamInfo(name="url", required=True), ParamInfo(name="scheme"), ParamInfo(name="allow_fragments")], min_args=1, max_args=3, return_type="ParseResult"),
        "urlunparse": FunctionSig(name="urlunparse", params=[ParamInfo(name="parts", required=True)], min_args=1, max_args=1, return_type="str"),
        "urljoin": FunctionSig(name="urljoin", params=[ParamInfo(name="base", required=True), ParamInfo(name="url", required=True), ParamInfo(name="allow_fragments")], min_args=2, max_args=3, return_type="str"),
        "urlencode": FunctionSig(name="urlencode", params=[ParamInfo(name="query", required=True), ParamInfo(name="doseq"), ParamInfo(name="safe"), ParamInfo(name="encoding")], min_args=1, max_args=4, return_type="str"),
        "quote": FunctionSig(name="quote", params=[ParamInfo(name="string", required=True), ParamInfo(name="safe"), ParamInfo(name="encoding")], min_args=1, max_args=3, return_type="str"),
        "unquote": FunctionSig(name="unquote", params=[ParamInfo(name="string", required=True), ParamInfo(name="encoding")], min_args=1, max_args=2, return_type="str"),
        "parse_qs": FunctionSig(name="parse_qs", params=[ParamInfo(name="qs", required=True), ParamInfo(name="keep_blank_values"), ParamInfo(name="strict_parsing")], min_args=1, max_args=-1, return_type="dict[str, list[str]]"),
        "parse_qsl": FunctionSig(name="parse_qsl", params=[ParamInfo(name="qs", required=True), ParamInfo(name="keep_blank_values"), ParamInfo(name="strict_parsing")], min_args=1, max_args=-1, return_type="list[tuple[str, str]]"),
        "urlsplit": FunctionSig(name="urlsplit", params=[ParamInfo(name="url", required=True), ParamInfo(name="scheme"), ParamInfo(name="allow_fragments")], min_args=1, max_args=3, return_type="SplitResult"),
        "urlunsplit": FunctionSig(name="urlunsplit", params=[ParamInfo(name="parts", required=True)], min_args=1, max_args=1, return_type="str"),
    },
    common_hallucinated_functions=["build_url", "normalize_url", "parse_query", "sanitize_url"],
)

_PY_ITERTOOLS: ModuleSig = ModuleSig(
    name="itertools",
    functions={
        "chain": FunctionSig(name="chain", min_args=0, max_args=-1, return_type="Iterator"),
        "product": FunctionSig(name="product", min_args=0, max_args=-1, return_type="Iterator[tuple]"),
        "combinations": FunctionSig(name="combinations", params=[ParamInfo(name="iterable", required=True), ParamInfo(name="r", required=True)], min_args=2, max_args=2, return_type="Iterator[tuple]"),
        "permutations": FunctionSig(name="permutations", params=[ParamInfo(name="iterable", required=True), ParamInfo(name="r")], min_args=1, max_args=2, return_type="Iterator[tuple]"),
        "count": FunctionSig(name="count", params=[ParamInfo(name="start"), ParamInfo(name="step")], min_args=0, max_args=2, return_type="Iterator[int]"),
        "cycle": FunctionSig(name="cycle", params=[ParamInfo(name="iterable", required=True)], min_args=1, max_args=1, return_type="Iterator"),
        "repeat": FunctionSig(name="repeat", params=[ParamInfo(name="object", required=True), ParamInfo(name="times")], min_args=1, max_args=2, return_type="Iterator"),
        "islice": FunctionSig(name="islice", min_args=2, max_args=-1, return_type="Iterator"),
        "tee": FunctionSig(name="tee", params=[ParamInfo(name="iterable", required=True), ParamInfo(name="n")], min_args=1, max_args=2, return_type="tuple[Iterator, ...]"),
        "zip_longest": FunctionSig(name="zip_longest", min_args=0, max_args=-1, return_type="Iterator[tuple]"),
        "groupby": FunctionSig(name="groupby", params=[ParamInfo(name="iterable", required=True), ParamInfo(name="key")], min_args=1, max_args=2, return_type="Iterator"),
        "accumulate": FunctionSig(name="accumulate", params=[ParamInfo(name="iterable", required=True), ParamInfo(name="func"), ParamInfo(name="initial")], min_args=1, max_args=3, return_type="Iterator"),
        "dropwhile": FunctionSig(name="dropwhile", params=[ParamInfo(name="predicate", required=True), ParamInfo(name="iterable", required=True)], min_args=2, max_args=2, return_type="Iterator"),
        "takewhile": FunctionSig(name="takewhile", params=[ParamInfo(name="predicate", required=True), ParamInfo(name="iterable", required=True)], min_args=2, max_args=2, return_type="Iterator"),
    },
    common_hallucinated_functions=["map", "filter", "flatten", "batch"],
)

_PY_FUNCTOOLS: ModuleSig = ModuleSig(
    name="functools",
    functions={
        "reduce": FunctionSig(name="reduce", params=[ParamInfo(name="function", required=True), ParamInfo(name="iterable", required=True), ParamInfo(name="initializer")], min_args=2, max_args=3, return_type="object"),
        "lru_cache": FunctionSig(name="lru_cache", params=[ParamInfo(name="maxsize"), ParamInfo(name="typed")], min_args=0, max_args=2, return_type="callable"),
        "partial": FunctionSig(name="partial", params=[ParamInfo(name="func", required=True)], min_args=1, max_args=-1, return_type="partial"),
        "wraps": FunctionSig(name="wraps", params=[ParamInfo(name="wrapped", required=True), ParamInfo(name="assigned"), ParamInfo(name="updated")], min_args=1, max_args=3, return_type="callable"),
        "singledispatch": FunctionSig(name="singledispatch", params=[ParamInfo(name="func", required=True)], min_args=1, max_args=1, return_type="function"),
        "total_ordering": FunctionSig(name="total_ordering", params=[ParamInfo(name="cls", required=True)], min_args=1, max_args=1, return_type="class"),
        "cached_property": FunctionSig(name="cached_property", params=[ParamInfo(name="func", required=True)], min_args=1, max_args=1, return_type="cached_property"),
        "cmp_to_key": FunctionSig(name="cmp_to_key", params=[ParamInfo(name="mycmp", required=True)], min_args=1, max_args=1, return_type="callable"),
    },
    common_hallucinated_functions=["memoize", "decorate", "cache_result", "compose"],
)

_JS_LODASH: ModuleSig = ModuleSig(
    name="lodash",
    functions={
        "map": FunctionSig(name="map", params=[ParamInfo(name="collection", required=True), ParamInfo(name="iteratee")], min_args=1, max_args=2, return_type="list"),
        "filter": FunctionSig(name="filter", params=[ParamInfo(name="collection", required=True), ParamInfo(name="predicate")], min_args=1, max_args=2, return_type="list"),
        "reduce": FunctionSig(name="reduce", params=[ParamInfo(name="collection", required=True), ParamInfo(name="iteratee", required=True), ParamInfo(name="accumulator")], min_args=2, max_args=3, return_type="object"),
        "cloneDeep": FunctionSig(name="cloneDeep", params=[ParamInfo(name="value", required=True)], min_args=1, max_args=1, return_type="object"),
        "merge": FunctionSig(name="merge", min_args=2, max_args=-1, return_type="object"),
        "get": FunctionSig(name="get", params=[ParamInfo(name="object", required=True), ParamInfo(name="path", required=True), ParamInfo(name="defaultValue")], min_args=2, max_args=3, return_type="object"),
        "set": FunctionSig(name="set", params=[ParamInfo(name="object", required=True), ParamInfo(name="path", required=True), ParamInfo(name="value", required=True)], min_args=3, max_args=3, return_type="object"),
        "debounce": FunctionSig(name="debounce", params=[ParamInfo(name="func", required=True), ParamInfo(name="wait", required=True), ParamInfo(name="options")], min_args=2, max_args=3, return_type="function"),
        "throttle": FunctionSig(name="throttle", params=[ParamInfo(name="func", required=True), ParamInfo(name="wait", required=True), ParamInfo(name="options")], min_args=2, max_args=3, return_type="function"),
        "uniq": FunctionSig(name="uniq", params=[ParamInfo(name="array", required=True)], min_args=1, max_args=1, return_type="list"),
        "sortBy": FunctionSig(name="sortBy", params=[ParamInfo(name="collection", required=True), ParamInfo(name="iteratees")], min_args=1, max_args=-1, return_type="list"),
        "groupBy": FunctionSig(name="groupBy", params=[ParamInfo(name="collection", required=True), ParamInfo(name="iteratee")], min_args=1, max_args=2, return_type="dict"),
        "keyBy": FunctionSig(name="keyBy", params=[ParamInfo(name="collection", required=True), ParamInfo(name="iteratee")], min_args=1, max_args=2, return_type="dict"),
        "pick": FunctionSig(name="pick", params=[ParamInfo(name="object", required=True)], min_args=1, max_args=-1, return_type="object"),
        "omit": FunctionSig(name="omit", params=[ParamInfo(name="object", required=True)], min_args=1, max_args=-1, return_type="object"),
    },
    common_hallucinated_functions=["pluck", "where", "extendDeep", "chainMap"],
)

_JS_DATE_FNS: ModuleSig = ModuleSig(
    name="date-fns",
    functions={
        "format": FunctionSig(name="format", params=[ParamInfo(name="date", required=True), ParamInfo(name="formatStr", required=True), ParamInfo(name="options")], min_args=2, max_args=3, return_type="string"),
        "parse": FunctionSig(name="parse", params=[ParamInfo(name="dateStr", required=True), ParamInfo(name="formatStr", required=True), ParamInfo(name="referenceDate", required=True), ParamInfo(name="options")], min_args=3, max_args=4, return_type="Date"),
        "parseISO": FunctionSig(name="parseISO", params=[ParamInfo(name="argument", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Date"),
        "formatISO": FunctionSig(name="formatISO", params=[ParamInfo(name="date", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="string"),
        "addDays": FunctionSig(name="addDays", params=[ParamInfo(name="date", required=True), ParamInfo(name="amount", required=True)], min_args=2, max_args=2, return_type="Date"),
        "subDays": FunctionSig(name="subDays", params=[ParamInfo(name="date", required=True), ParamInfo(name="amount", required=True)], min_args=2, max_args=2, return_type="Date"),
        "differenceInDays": FunctionSig(name="differenceInDays", params=[ParamInfo(name="dateLeft", required=True), ParamInfo(name="dateRight", required=True)], min_args=2, max_args=2, return_type="number"),
        "startOfDay": FunctionSig(name="startOfDay", params=[ParamInfo(name="date", required=True)], min_args=1, max_args=1, return_type="Date"),
        "endOfDay": FunctionSig(name="endOfDay", params=[ParamInfo(name="date", required=True)], min_args=1, max_args=1, return_type="Date"),
        "isAfter": FunctionSig(name="isAfter", params=[ParamInfo(name="date", required=True), ParamInfo(name="dateToCompare", required=True)], min_args=2, max_args=2, return_type="bool"),
        "isBefore": FunctionSig(name="isBefore", params=[ParamInfo(name="date", required=True), ParamInfo(name="dateToCompare", required=True)], min_args=2, max_args=2, return_type="bool"),
        "isValid": FunctionSig(name="isValid", params=[ParamInfo(name="date", required=True)], min_args=1, max_args=1, return_type="bool"),
    },
    common_hallucinated_functions=["toDate", "fromNow", "utc", "timezone"],
)

_JS_RXJS: ModuleSig = ModuleSig(
    name="rxjs",
    functions={
        "of": FunctionSig(name="of", min_args=0, max_args=-1, return_type="Observable"),
        "from": FunctionSig(name="from", params=[ParamInfo(name="input", required=True)], min_args=1, max_args=1, return_type="Observable"),
        "map": FunctionSig(name="map", params=[ParamInfo(name="project", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "filter": FunctionSig(name="filter", params=[ParamInfo(name="predicate", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "switchMap": FunctionSig(name="switchMap", params=[ParamInfo(name="project", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "mergeMap": FunctionSig(name="mergeMap", params=[ParamInfo(name="project", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "catchError": FunctionSig(name="catchError", params=[ParamInfo(name="selector", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "tap": FunctionSig(name="tap", min_args=0, max_args=-1, return_type="OperatorFunction"),
        "debounceTime": FunctionSig(name="debounceTime", params=[ParamInfo(name="dueTime", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "throttleTime": FunctionSig(name="throttleTime", params=[ParamInfo(name="duration", required=True)], min_args=1, max_args=-1, return_type="OperatorFunction"),
        "take": FunctionSig(name="take", params=[ParamInfo(name="count", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "takeUntil": FunctionSig(name="takeUntil", params=[ParamInfo(name="notifier", required=True)], min_args=1, max_args=1, return_type="OperatorFunction"),
        "combineLatest": FunctionSig(name="combineLatest", params=[ParamInfo(name="sources", required=True)], min_args=1, max_args=-1, return_type="Observable"),
        "forkJoin": FunctionSig(name="forkJoin", params=[ParamInfo(name="sources", required=True)], min_args=1, max_args=-1, return_type="Observable"),
    },
    common_hallucinated_functions=["subscribeMap", "pipeMap", "promise", "await"],
)

_JS_JEST: ModuleSig = ModuleSig(
    name="jest",
    functions={
        "describe": FunctionSig(name="describe", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True)], min_args=2, max_args=2, return_type="void"),
        "it": FunctionSig(name="it", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=2, max_args=3, return_type="void"),
        "test": FunctionSig(name="test", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=2, max_args=3, return_type="void"),
        "expect": FunctionSig(name="expect", params=[ParamInfo(name="value", required=True)], min_args=1, max_args=1, return_type="Matchers"),
        "beforeEach": FunctionSig(name="beforeEach", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "afterEach": FunctionSig(name="afterEach", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "beforeAll": FunctionSig(name="beforeAll", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "afterAll": FunctionSig(name="afterAll", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "fn": FunctionSig(name="fn", params=[ParamInfo(name="implementation")], min_args=0, max_args=1, return_type="Mock"),
        "spyOn": FunctionSig(name="spyOn", params=[ParamInfo(name="object", required=True), ParamInfo(name="methodName", required=True)], min_args=2, max_args=2, return_type="SpyInstance"),
        "mock": FunctionSig(name="mock", params=[ParamInfo(name="moduleName", required=True), ParamInfo(name="factory"), ParamInfo(name="options")], min_args=1, max_args=3, return_type="void"),
        "clearAllMocks": FunctionSig(name="clearAllMocks", min_args=0, max_args=0, return_type="void"),
    },
    common_hallucinated_functions=["assert", "stub", "verify", "fixture"],
)

_JS_VITEST: ModuleSig = ModuleSig(
    name="vitest",
    functions={
        "describe": FunctionSig(name="describe", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True)], min_args=2, max_args=2, return_type="void"),
        "it": FunctionSig(name="it", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=2, max_args=3, return_type="void"),
        "test": FunctionSig(name="test", params=[ParamInfo(name="name", required=True), ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=2, max_args=3, return_type="void"),
        "expect": FunctionSig(name="expect", params=[ParamInfo(name="value", required=True)], min_args=1, max_args=1, return_type="Assertion"),
        "beforeEach": FunctionSig(name="beforeEach", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "afterEach": FunctionSig(name="afterEach", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "beforeAll": FunctionSig(name="beforeAll", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "afterAll": FunctionSig(name="afterAll", params=[ParamInfo(name="fn", required=True), ParamInfo(name="timeout")], min_args=1, max_args=2, return_type="void"),
        "fn": FunctionSig(name="fn", params=[ParamInfo(name="implementation")], min_args=0, max_args=1, return_type="Mock"),
        "spyOn": FunctionSig(name="spyOn", params=[ParamInfo(name="object", required=True), ParamInfo(name="methodName", required=True)], min_args=2, max_args=2, return_type="MockInstance"),
        "mock": FunctionSig(name="mock", params=[ParamInfo(name="path", required=True), ParamInfo(name="factory")], min_args=1, max_args=2, return_type="void"),
        "clearAllMocks": FunctionSig(name="clearAllMocks", min_args=0, max_args=0, return_type="void"),
    },
    common_hallucinated_functions=["assert", "fixture", "suite", "spy"],
)

_JS_FS_PROMISES: ModuleSig = ModuleSig(
    name="fs/promises",
    functions={
        "readFile": FunctionSig(name="readFile", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "writeFile": FunctionSig(name="writeFile", params=[ParamInfo(name="file", required=True), ParamInfo(name="data", required=True), ParamInfo(name="options")], min_args=2, max_args=3, return_type="Promise"),
        "appendFile": FunctionSig(name="appendFile", params=[ParamInfo(name="path", required=True), ParamInfo(name="data", required=True), ParamInfo(name="options")], min_args=2, max_args=3, return_type="Promise"),
        "readdir": FunctionSig(name="readdir", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "mkdir": FunctionSig(name="mkdir", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "rm": FunctionSig(name="rm", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "stat": FunctionSig(name="stat", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "lstat": FunctionSig(name="lstat", params=[ParamInfo(name="path", required=True), ParamInfo(name="options")], min_args=1, max_args=2, return_type="Promise"),
        "access": FunctionSig(name="access", params=[ParamInfo(name="path", required=True), ParamInfo(name="mode")], min_args=1, max_args=2, return_type="Promise"),
        "copyFile": FunctionSig(name="copyFile", params=[ParamInfo(name="src", required=True), ParamInfo(name="dest", required=True), ParamInfo(name="mode")], min_args=2, max_args=3, return_type="Promise"),
        "rename": FunctionSig(name="rename", params=[ParamInfo(name="oldPath", required=True), ParamInfo(name="newPath", required=True)], min_args=2, max_args=2, return_type="Promise"),
        "unlink": FunctionSig(name="unlink", params=[ParamInfo(name="path", required=True)], min_args=1, max_args=1, return_type="Promise"),
    },
    common_hallucinated_functions=["exists", "ensureDir", "delete", "copy"],
)

_JS_URL: ModuleSig = ModuleSig(
    name="url",
    functions={
        "URL": FunctionSig(name="URL", params=[ParamInfo(name="input", required=True), ParamInfo(name="base")], min_args=1, max_args=2, return_type="URL"),
        "URLSearchParams": FunctionSig(name="URLSearchParams", params=[ParamInfo(name="init")], min_args=0, max_args=1, return_type="URLSearchParams"),
        "fileURLToPath": FunctionSig(name="fileURLToPath", params=[ParamInfo(name="url", required=True)], min_args=1, max_args=1, return_type="string"),
        "pathToFileURL": FunctionSig(name="pathToFileURL", params=[ParamInfo(name="path", required=True)], min_args=1, max_args=1, return_type="URL"),
        "domainToASCII": FunctionSig(name="domainToASCII", params=[ParamInfo(name="domain", required=True)], min_args=1, max_args=1, return_type="string"),
        "domainToUnicode": FunctionSig(name="domainToUnicode", params=[ParamInfo(name="domain", required=True)], min_args=1, max_args=1, return_type="string"),
        "format": FunctionSig(name="format", params=[ParamInfo(name="urlObject", required=True)], min_args=1, max_args=1, return_type="string"),
        "parse": FunctionSig(name="parse", params=[ParamInfo(name="urlStr", required=True), ParamInfo(name="parseQueryString"), ParamInfo(name="slashesDenoteHost")], min_args=1, max_args=3, return_type="UrlWithStringQuery"),
        "resolve": FunctionSig(name="resolve", params=[ParamInfo(name="from", required=True), ParamInfo(name="to", required=True)], min_args=2, max_args=2, return_type="string"),
    },
    common_hallucinated_functions=["toURL", "normalize", "sanitize", "build"],
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
    "subprocess": _PY_SUBPROCESS,
    "re": _PY_RE,
    "datetime": _PY_DATETIME,
    "hashlib": _PY_HASHLIB,
    "collections": _PY_COLLECTIONS,
    "openai": _PY_OPENAI,
    "asyncio": _PY_ASYNCIO,
    "sys": _PY_SYS,
    "math": _PY_MATH,
    "statistics": _PY_STATISTICS,
    "uuid": _PY_UUID,
    "shutil": _PY_SHUTIL,
    "tempfile": _PY_TEMPFILE,
    "csv": _PY_CSV,
    "sqlite3": _PY_SQLITE3,
    "urllib.parse": _PY_URLLIB_PARSE,
    "itertools": _PY_ITERTOOLS,
    "functools": _PY_FUNCTOOLS,
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
    "crypto": _JS_CRYPTO,
    "node:crypto": _JS_CRYPTO,
    "http": _JS_HTTP,
    "node:http": _JS_HTTP,
    "child_process": _JS_CHILD_PROCESS,
    "node:child_process": _JS_CHILD_PROCESS,
    "next/navigation": _JS_NEXT,
    "lodash": _JS_LODASH,
    "date-fns": _JS_DATE_FNS,
    "rxjs": _JS_RXJS,
    "jest": _JS_JEST,
    "vitest": _JS_VITEST,
    "fs/promises": _JS_FS_PROMISES,
    "node:fs/promises": _JS_FS_PROMISES,
    "url": _JS_URL,
    "node:url": _JS_URL,
}

SIGNATURES: dict[str, dict[str, ModuleSig]] = {
    "python": PYTHON_SIGNATURES,
    "javascript": JS_TS_SIGNATURES,
    "typescript": JS_TS_SIGNATURES,
}

# Total counts for metrics — deduplicate aliases and shared dicts
_UNIQUE_PY_MODULES = {sig.name for sig in PYTHON_SIGNATURES.values()}
_UNIQUE_JS_MODULES = {sig.name for sig in JS_TS_SIGNATURES.values()}
TOTAL_MODULES = len(_UNIQUE_PY_MODULES) + len(_UNIQUE_JS_MODULES)

def _count_unique_functions() -> int:
    """Count unique functions across all modules, avoiding double-counting."""
    total = 0
    seen_modules: set[str] = set()
    # Only iterate unique language dicts (python + js/ts, not both js AND ts)
    for sigs in (PYTHON_SIGNATURES, JS_TS_SIGNATURES):
        for module_sig in sigs.values():
            if module_sig.name in seen_modules:
                continue
            seen_modules.add(module_sig.name)
            total += len(module_sig.functions)
            for sub_funcs in module_sig.submodules.values():
                total += len(sub_funcs)
    return total

TOTAL_FUNCTIONS = _count_unique_functions()
