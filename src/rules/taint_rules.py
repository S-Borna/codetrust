# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Taint analysis source/sink definitions for data flow tracking.

Defines taxonomies of taint sources (where untrusted data enters),
sinks (where tainted data causes vulnerabilities), and sanitizers
(functions that neutralize taint).
"""

from dataclasses import dataclass

from src.models.enums import Language


@dataclass(frozen=True)
class TaintSource:
    """A function or attribute that introduces untrusted data."""

    name: str
    pattern: str
    language: Language
    description: str = ""


@dataclass(frozen=True)
class TaintSink:
    """A dangerous function where tainted data causes vulnerabilities."""

    name: str
    pattern: str
    category: str
    language: Language
    description: str = ""


@dataclass(frozen=True)
class TaintSanitizer:
    """A function that neutralizes tainted data."""

    name: str
    pattern: str
    language: Language
    description: str = ""


# ═══════════════════════════════════════════════════════════════
#  TAINT SOURCES — where untrusted data enters the program
# ═══════════════════════════════════════════════════════════════

PYTHON_SOURCES: tuple[TaintSource, ...] = (
    TaintSource("request.args", "request.args", Language.PYTHON, "Flask query parameters"),
    TaintSource("request.form", "request.form", Language.PYTHON, "Flask form data"),
    TaintSource("request.json", "request.json", Language.PYTHON, "Flask JSON body"),
    TaintSource("request.get_json", "request.get_json(", Language.PYTHON, "Flask JSON body method"),
    TaintSource("request.data", "request.data", Language.PYTHON, "Flask raw request data"),
    TaintSource("request.params", "request.params", Language.PYTHON, "Request parameters"),
    TaintSource("request.query_params", "request.query_params", Language.PYTHON, "FastAPI query params"),
    TaintSource("input", "input(", Language.PYTHON, "Standard input"),
    TaintSource("sys.stdin", "sys.stdin", Language.PYTHON, "Standard input stream"),
    TaintSource("os.environ.get", "os.environ.get(", Language.PYTHON, "Environment variable"),
)

JAVASCRIPT_SOURCES: tuple[TaintSource, ...] = (
    TaintSource("req.body", "req.body", Language.JAVASCRIPT, "Express request body"),
    TaintSource("req.params", "req.params", Language.JAVASCRIPT, "Express URL parameters"),
    TaintSource("req.query", "req.query", Language.JAVASCRIPT, "Express query string"),
    TaintSource("req.headers", "req.headers", Language.JAVASCRIPT, "Express request headers"),
    TaintSource("window.location", "window.location", Language.JAVASCRIPT, "Browser URL"),
    TaintSource("document.URL", "document.URL", Language.JAVASCRIPT, "Document URL"),
    TaintSource("document.cookie", "document.cookie", Language.JAVASCRIPT, "Browser cookies"),
    TaintSource("location.search", "location.search", Language.JAVASCRIPT, "URL search params"),
    TaintSource("location.hash", "location.hash", Language.JAVASCRIPT, "URL hash fragment"),
)

GO_SOURCES: tuple[TaintSource, ...] = (
    TaintSource("r.URL.Query", "r.URL.Query(", Language.GO, "HTTP query parameters"),
    TaintSource("r.FormValue", "r.FormValue(", Language.GO, "Form field value"),
    TaintSource("r.Body", "r.Body", Language.GO, "HTTP request body"),
    TaintSource("r.Header.Get", "r.Header.Get(", Language.GO, "HTTP request header"),
)

JAVA_SOURCES: tuple[TaintSource, ...] = (
    TaintSource("request.getParameter", "request.getParameter(", Language.JAVA, "Servlet parameter"),
    TaintSource("request.getInputStream", "request.getInputStream(", Language.JAVA, "Servlet input stream"),
    TaintSource("request.getHeader", "request.getHeader(", Language.JAVA, "Servlet request header"),
)

TAINT_SOURCES: dict[Language, tuple[TaintSource, ...]] = {
    Language.PYTHON: PYTHON_SOURCES,
    Language.JAVASCRIPT: JAVASCRIPT_SOURCES,
    Language.TYPESCRIPT: JAVASCRIPT_SOURCES,
    Language.GO: GO_SOURCES,
    Language.JAVA: JAVA_SOURCES,
}


# ═══════════════════════════════════════════════════════════════
#  TAINT SINKS — where tainted data causes vulnerabilities
# ═══════════════════════════════════════════════════════════════

CATEGORY_SQL_INJECTION = "sql_injection"
CATEGORY_COMMAND_INJECTION = "command_injection"
CATEGORY_XSS = "xss"
CATEGORY_PATH_TRAVERSAL = "path_traversal"
CATEGORY_SSRF = "ssrf"
CATEGORY_DESERIALIZATION = "deserialization"

PYTHON_SINKS: tuple[TaintSink, ...] = (
    # SQL injection
    TaintSink("cursor.execute", "cursor.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("db.query", "db.query(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("db.execute", "db.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("connection.execute", "connection.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    # Command injection
    TaintSink("os.system", "os.system(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("os.popen", "os.popen(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.run", "subprocess.run(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.call", "subprocess.call(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.Popen", "subprocess.Popen(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    # Path traversal
    TaintSink("open", "open(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("os.path.join", "os.path.join(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("shutil.copy", "shutil.copy(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    # SSRF
    TaintSink("requests.get", "requests.get(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("requests.post", "requests.post(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("httpx.get", "httpx.get(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("urllib.request.urlopen", "urllib.request.urlopen(", CATEGORY_SSRF, Language.PYTHON),
    # Deserialization
    TaintSink("pickle.loads", "pickle.loads(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("yaml.load", "yaml.load(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    # XSS
    TaintSink("render_template_string", "render_template_string(", CATEGORY_XSS, Language.PYTHON),
)

JAVASCRIPT_SINKS: tuple[TaintSink, ...] = (
    # SQL injection
    TaintSink("db.query", "db.query(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    TaintSink("db.execute", "db.execute(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    TaintSink(".rawQuery", ".rawQuery(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    # Command injection
    TaintSink("child_process.exec", "child_process.exec(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    TaintSink("exec", "exec(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    # XSS
    TaintSink("innerHTML", ".innerHTML", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("document.write", "document.write(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("response.write", "response.write(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("res.send", "res.send(", CATEGORY_XSS, Language.JAVASCRIPT),
    # Path traversal
    TaintSink("fs.readFile", "fs.readFile(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("fs.writeFile", "fs.writeFile(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    # SSRF
    TaintSink("fetch", "fetch(", CATEGORY_SSRF, Language.JAVASCRIPT),
    # Deserialization
    TaintSink("eval", "eval(", CATEGORY_DESERIALIZATION, Language.JAVASCRIPT),
)

GO_SINKS: tuple[TaintSink, ...] = (
    # SQL injection
    TaintSink("db.Query", "db.Query(", CATEGORY_SQL_INJECTION, Language.GO),
    TaintSink("db.Exec", "db.Exec(", CATEGORY_SQL_INJECTION, Language.GO),
    TaintSink("db.QueryRow", "db.QueryRow(", CATEGORY_SQL_INJECTION, Language.GO),
    # Command injection
    TaintSink("exec.Command", "exec.Command(", CATEGORY_COMMAND_INJECTION, Language.GO),
    # XSS
    TaintSink("template.HTML", "template.HTML(", CATEGORY_XSS, Language.GO),
    # Path traversal
    TaintSink("os.Create", "os.Create(", CATEGORY_PATH_TRAVERSAL, Language.GO),
    TaintSink("os.Open", "os.Open(", CATEGORY_PATH_TRAVERSAL, Language.GO),
    TaintSink("ioutil.ReadFile", "ioutil.ReadFile(", CATEGORY_PATH_TRAVERSAL, Language.GO),
    # SSRF
    TaintSink("http.Get", "http.Get(", CATEGORY_SSRF, Language.GO),
    TaintSink("http.Post", "http.Post(", CATEGORY_SSRF, Language.GO),
)

JAVA_SINKS: tuple[TaintSink, ...] = (
    TaintSink(".rawQuery", ".rawQuery(", CATEGORY_SQL_INJECTION, Language.JAVA),
)

TAINT_SINKS: dict[Language, tuple[TaintSink, ...]] = {
    Language.PYTHON: PYTHON_SINKS,
    Language.JAVASCRIPT: JAVASCRIPT_SINKS,
    Language.TYPESCRIPT: JAVASCRIPT_SINKS,
    Language.GO: GO_SINKS,
    Language.JAVA: JAVA_SINKS,
}


# ═══════════════════════════════════════════════════════════════
#  TAINT SANITIZERS — functions that neutralize taint
# ═══════════════════════════════════════════════════════════════

PYTHON_SANITIZERS: tuple[TaintSanitizer, ...] = (
    TaintSanitizer("int", "int(", Language.PYTHON, "Integer cast"),
    TaintSanitizer("float", "float(", Language.PYTHON, "Float cast"),
    TaintSanitizer("str.strip", ".strip(", Language.PYTHON, "String strip"),
    TaintSanitizer("escape", "escape(", Language.PYTHON, "HTML escape"),
    TaintSanitizer("bleach.clean", "bleach.clean(", Language.PYTHON, "HTML sanitizer"),
    TaintSanitizer("markupsafe.escape", "markupsafe.escape(", Language.PYTHON, "Markup escape"),
    TaintSanitizer("shlex.quote", "shlex.quote(", Language.PYTHON, "Shell quoting"),
    TaintSanitizer("parameterized_query", "%(", Language.PYTHON, "Parameterized SQL"),
)

JAVASCRIPT_SANITIZERS: tuple[TaintSanitizer, ...] = (
    TaintSanitizer("parseInt", "parseInt(", Language.JAVASCRIPT, "Integer parse"),
    TaintSanitizer("parseFloat", "parseFloat(", Language.JAVASCRIPT, "Float parse"),
    TaintSanitizer("Number", "Number(", Language.JAVASCRIPT, "Number cast"),
    TaintSanitizer("encodeURIComponent", "encodeURIComponent(", Language.JAVASCRIPT, "URI encode"),
    TaintSanitizer("DOMPurify.sanitize", "DOMPurify.sanitize(", Language.JAVASCRIPT, "DOM sanitizer"),
)

GO_SANITIZERS: tuple[TaintSanitizer, ...] = (
    TaintSanitizer("strconv.Atoi", "strconv.Atoi(", Language.GO, "String to int conversion"),
    TaintSanitizer("strconv.ParseInt", "strconv.ParseInt(", Language.GO, "String to int64 conversion"),
    TaintSanitizer("strconv.ParseFloat", "strconv.ParseFloat(", Language.GO, "String to float conversion"),
    TaintSanitizer("html.EscapeString", "html.EscapeString(", Language.GO, "HTML escape"),
    TaintSanitizer("url.QueryEscape", "url.QueryEscape(", Language.GO, "URL query escape"),
    TaintSanitizer("filepath.Clean", "filepath.Clean(", Language.GO, "File path sanitization"),
)

TAINT_SANITIZERS: dict[Language, tuple[TaintSanitizer, ...]] = {
    Language.PYTHON: PYTHON_SANITIZERS,
    Language.JAVASCRIPT: JAVASCRIPT_SANITIZERS,
    Language.TYPESCRIPT: JAVASCRIPT_SANITIZERS,
    Language.GO: GO_SANITIZERS,
}
