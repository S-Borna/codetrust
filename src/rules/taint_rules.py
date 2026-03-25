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
    # Servlet API
    TaintSource("request.getParameter", "request.getParameter(", Language.JAVA, "Servlet parameter"),
    TaintSource("request.getParameterValues", "request.getParameterValues(", Language.JAVA, "Servlet multi-value parameter"),
    TaintSource("request.getInputStream", "request.getInputStream(", Language.JAVA, "Servlet input stream"),
    TaintSource("request.getHeader", "request.getHeader(", Language.JAVA, "Servlet request header"),
    TaintSource("request.getQueryString", "request.getQueryString(", Language.JAVA, "Servlet raw query string"),
    TaintSource("request.getPathInfo", "request.getPathInfo(", Language.JAVA, "Servlet path info"),
    TaintSource("request.getCookies", "request.getCookies(", Language.JAVA, "Servlet cookies"),
    TaintSource("request.getRequestURI", "request.getRequestURI(", Language.JAVA, "Servlet request URI"),
    # Spring MVC
    TaintSource("@RequestParam", "@RequestParam", Language.JAVA, "Spring MVC query/form parameter"),
    TaintSource("@PathVariable", "@PathVariable", Language.JAVA, "Spring MVC URL path variable"),
    TaintSource("@RequestBody", "@RequestBody", Language.JAVA, "Spring MVC JSON request body"),
    TaintSource("@RequestHeader", "@RequestHeader", Language.JAVA, "Spring MVC request header"),
    TaintSource("@CookieValue", "@CookieValue", Language.JAVA, "Spring MVC cookie value"),
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
CATEGORY_CODE_INJECTION = "code_injection"
CATEGORY_XSS = "xss"
CATEGORY_PATH_TRAVERSAL = "path_traversal"
CATEGORY_SSRF = "ssrf"
CATEGORY_DESERIALIZATION = "deserialization"
CATEGORY_LDAP_INJECTION = "ldap_injection"

PYTHON_SINKS: tuple[TaintSink, ...] = (
    # SQL injection
    TaintSink("cursor.execute", "cursor.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("cursor.executemany", "cursor.executemany(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("db.query", "db.query(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("db.execute", "db.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("connection.execute", "connection.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON),
    TaintSink("session.execute", "session.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON, "SQLAlchemy session"),
    TaintSink("engine.execute", "engine.execute(", CATEGORY_SQL_INJECTION, Language.PYTHON, "SQLAlchemy engine"),
    TaintSink("text(", "text(", CATEGORY_SQL_INJECTION, Language.PYTHON, "SQLAlchemy text() with concat"),
    # Command injection
    TaintSink("os.system", "os.system(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("os.popen", "os.popen(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("os.exec", "os.exec", CATEGORY_COMMAND_INJECTION, Language.PYTHON, "os.execl/execv family"),
    TaintSink("subprocess.run", "subprocess.run(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.call", "subprocess.call(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.Popen", "subprocess.Popen(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    TaintSink("subprocess.check_output", "subprocess.check_output(", CATEGORY_COMMAND_INJECTION, Language.PYTHON),
    # Path traversal
    TaintSink("open", "open(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("os.path.join", "os.path.join(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("pathlib.Path", "Path(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON, "Path construction from user input"),
    TaintSink("shutil.copy", "shutil.copy(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("shutil.move", "shutil.move(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("os.rename", "os.rename(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("os.remove", "os.remove(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    TaintSink("os.makedirs", "os.makedirs(", CATEGORY_PATH_TRAVERSAL, Language.PYTHON),
    # SSRF
    TaintSink("requests.get", "requests.get(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("requests.post", "requests.post(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("requests.put", "requests.put(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("requests.delete", "requests.delete(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("httpx.get", "httpx.get(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("httpx.post", "httpx.post(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("urllib.request.urlopen", "urllib.request.urlopen(", CATEGORY_SSRF, Language.PYTHON),
    TaintSink("aiohttp.request", "aiohttp.request(", CATEGORY_SSRF, Language.PYTHON),
    # Deserialization
    TaintSink("pickle.loads", "pickle.loads(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("pickle.load", "pickle.load(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("yaml.load", "yaml.load(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("yaml.unsafe_load", "yaml.unsafe_load(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("jsonpickle.decode", "jsonpickle.decode(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    TaintSink("marshal.loads", "marshal.loads(", CATEGORY_DESERIALIZATION, Language.PYTHON),
    # XSS
    TaintSink("render_template_string", "render_template_string(", CATEGORY_XSS, Language.PYTHON),
    TaintSink("Template", "Template(", CATEGORY_XSS, Language.PYTHON, "Jinja2/string Template with concat"),
    TaintSink("Markup", "Markup(", CATEGORY_XSS, Language.PYTHON, "markupsafe.Markup bypasses escaping"),
    # Code injection
    TaintSink("eval", "eval(", CATEGORY_CODE_INJECTION, Language.PYTHON, "Dynamic code execution"),
    TaintSink("exec", "exec(", CATEGORY_CODE_INJECTION, Language.PYTHON, "Dynamic code execution"),
    TaintSink("compile", "compile(", CATEGORY_CODE_INJECTION, Language.PYTHON, "Code compilation from string"),
    TaintSink("__import__", "__import__(", CATEGORY_CODE_INJECTION, Language.PYTHON, "Dynamic import"),
    # LDAP injection
    TaintSink("ldap.search_s", "search_s(", CATEGORY_LDAP_INJECTION, Language.PYTHON, "LDAP search"),
    TaintSink("ldap.search", "search(", CATEGORY_LDAP_INJECTION, Language.PYTHON, "LDAP async search"),
)

JAVASCRIPT_SINKS: tuple[TaintSink, ...] = (
    # SQL injection
    TaintSink("db.query", "db.query(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    TaintSink("db.execute", "db.execute(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    TaintSink(".rawQuery", ".rawQuery(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT),
    TaintSink("sequelize.query", ".query(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT, "Sequelize raw query"),
    TaintSink("knex.raw", ".raw(", CATEGORY_SQL_INJECTION, Language.JAVASCRIPT, "Knex raw query"),
    # Command injection
    TaintSink("child_process.exec", "child_process.exec(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    TaintSink("child_process.execSync", "child_process.execSync(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    TaintSink("child_process.spawn", "child_process.spawn(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    TaintSink("exec", "exec(", CATEGORY_COMMAND_INJECTION, Language.JAVASCRIPT),
    # XSS
    TaintSink("innerHTML", ".innerHTML", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("outerHTML", ".outerHTML", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("document.write", "document.write(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("document.writeln", "document.writeln(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("insertAdjacentHTML", ".insertAdjacentHTML(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("response.write", "response.write(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("res.send", "res.send(", CATEGORY_XSS, Language.JAVASCRIPT),
    TaintSink("dangerouslySetInnerHTML", "dangerouslySetInnerHTML", CATEGORY_XSS, Language.JAVASCRIPT, "React unsafe HTML"),
    # Path traversal
    TaintSink("fs.readFile", "fs.readFile(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("fs.readFileSync", "fs.readFileSync(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("fs.writeFile", "fs.writeFile(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("fs.writeFileSync", "fs.writeFileSync(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("fs.unlink", "fs.unlink(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("path.join", "path.join(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    TaintSink("path.resolve", "path.resolve(", CATEGORY_PATH_TRAVERSAL, Language.JAVASCRIPT),
    # SSRF
    TaintSink("fetch", "fetch(", CATEGORY_SSRF, Language.JAVASCRIPT),
    TaintSink("axios.get", "axios.get(", CATEGORY_SSRF, Language.JAVASCRIPT),
    TaintSink("axios.post", "axios.post(", CATEGORY_SSRF, Language.JAVASCRIPT),
    TaintSink("http.request", "http.request(", CATEGORY_SSRF, Language.JAVASCRIPT),
    # Code injection / deserialization
    TaintSink("eval", "eval(", CATEGORY_CODE_INJECTION, Language.JAVASCRIPT),
    TaintSink("Function", "Function(", CATEGORY_CODE_INJECTION, Language.JAVASCRIPT, "Dynamic function creation"),
    TaintSink("setTimeout_string", "setTimeout(", CATEGORY_CODE_INJECTION, Language.JAVASCRIPT, "setTimeout with string arg"),
    TaintSink("vm.runInContext", "vm.runInContext(", CATEGORY_CODE_INJECTION, Language.JAVASCRIPT, "VM code execution"),
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
    # SQL injection — JDBC
    TaintSink("Statement.execute", ".execute(", CATEGORY_SQL_INJECTION, Language.JAVA, "JDBC Statement.execute"),
    TaintSink("Statement.executeQuery", ".executeQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "JDBC Statement.executeQuery"),
    TaintSink("Statement.executeUpdate", ".executeUpdate(", CATEGORY_SQL_INJECTION, Language.JAVA, "JDBC Statement.executeUpdate"),
    TaintSink("Connection.prepareStatement", ".prepareStatement(", CATEGORY_SQL_INJECTION, Language.JAVA, "SQL in PreparedStatement creation"),
    TaintSink("Connection.nativeQuery", ".nativeQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "JPA native query"),
    # SQL injection — Hibernate / JPA
    TaintSink("Session.createQuery", ".createQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "Hibernate HQL query"),
    TaintSink("Session.createSQLQuery", ".createSQLQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "Hibernate native SQL"),
    TaintSink("EntityManager.createNativeQuery", ".createNativeQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "JPA native SQL query"),
    TaintSink("EntityManager.createQuery", ".createQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "JPA/JPQL query"),
    # SQL injection — Spring JDBC
    TaintSink("JdbcTemplate.query", "jdbcTemplate.query(", CATEGORY_SQL_INJECTION, Language.JAVA, "Spring JdbcTemplate query"),
    TaintSink("JdbcTemplate.update", "jdbcTemplate.update(", CATEGORY_SQL_INJECTION, Language.JAVA, "Spring JdbcTemplate update"),
    TaintSink("JdbcTemplate.execute", "jdbcTemplate.execute(", CATEGORY_SQL_INJECTION, Language.JAVA, "Spring JdbcTemplate execute"),
    TaintSink("NamedParameterJdbcTemplate.query", "namedParameterJdbcTemplate.query(", CATEGORY_SQL_INJECTION, Language.JAVA, "Spring named JDBC query"),
    TaintSink(".rawQuery", ".rawQuery(", CATEGORY_SQL_INJECTION, Language.JAVA, "Android raw SQL query"),
    # Command injection
    TaintSink("Runtime.exec", "Runtime.getRuntime().exec(", CATEGORY_COMMAND_INJECTION, Language.JAVA, "Java Runtime.exec"),
    TaintSink("ProcessBuilder", "new ProcessBuilder(", CATEGORY_COMMAND_INJECTION, Language.JAVA, "Java ProcessBuilder"),
    # XSS — Servlet response
    TaintSink("response.getWriter", "response.getWriter().print", CATEGORY_XSS, Language.JAVA, "Servlet response writer"),
    TaintSink("PrintWriter.println", ".println(", CATEGORY_XSS, Language.JAVA, "Servlet PrintWriter output"),
    # Path traversal
    TaintSink("new File", "new File(", CATEGORY_PATH_TRAVERSAL, Language.JAVA, "File path construction"),
    TaintSink("Paths.get", "Paths.get(", CATEGORY_PATH_TRAVERSAL, Language.JAVA, "NIO path construction"),
    TaintSink("FileInputStream", "new FileInputStream(", CATEGORY_PATH_TRAVERSAL, Language.JAVA, "File input stream"),
    TaintSink("FileOutputStream", "new FileOutputStream(", CATEGORY_PATH_TRAVERSAL, Language.JAVA, "File output stream"),
    # SSRF
    TaintSink("URL.openConnection", ".openConnection(", CATEGORY_SSRF, Language.JAVA, "Java URL connection"),
    TaintSink("HttpClient.send", "httpClient.send(", CATEGORY_SSRF, Language.JAVA, "Java 11+ HttpClient"),
    TaintSink("RestTemplate.getForObject", "restTemplate.getForObject(", CATEGORY_SSRF, Language.JAVA, "Spring RestTemplate GET"),
    TaintSink("RestTemplate.postForObject", "restTemplate.postForObject(", CATEGORY_SSRF, Language.JAVA, "Spring RestTemplate POST"),
    TaintSink("WebClient.get", "webClient.get(", CATEGORY_SSRF, Language.JAVA, "Spring WebFlux WebClient"),
    # Deserialization
    TaintSink("ObjectInputStream.readObject", ".readObject(", CATEGORY_DESERIALIZATION, Language.JAVA, "Java deserialization"),
    TaintSink("XMLDecoder.readObject", ".readObject(", CATEGORY_DESERIALIZATION, Language.JAVA, "XML deserialization"),
    # Code injection
    TaintSink("ScriptEngine.eval", ".eval(", CATEGORY_CODE_INJECTION, Language.JAVA, "Java ScriptEngine eval"),
    # LDAP injection
    TaintSink("DirContext.search", ".search(", CATEGORY_LDAP_INJECTION, Language.JAVA, "JNDI LDAP search"),
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
    # Type casting (breaks string taint)
    TaintSanitizer("int", "int(", Language.PYTHON, "Integer cast"),
    TaintSanitizer("float", "float(", Language.PYTHON, "Float cast"),
    TaintSanitizer("bool", "bool(", Language.PYTHON, "Boolean cast"),
    TaintSanitizer("uuid.UUID", "UUID(", Language.PYTHON, "UUID validation/cast"),
    # HTML/XSS sanitization
    TaintSanitizer("escape", "escape(", Language.PYTHON, "HTML escape"),
    TaintSanitizer("bleach.clean", "bleach.clean(", Language.PYTHON, "HTML sanitizer"),
    TaintSanitizer("markupsafe.escape", "markupsafe.escape(", Language.PYTHON, "Markup escape"),
    TaintSanitizer("html.escape", "html.escape(", Language.PYTHON, "stdlib HTML escape"),
    TaintSanitizer("cgi.escape", "cgi.escape(", Language.PYTHON, "Legacy CGI escape"),
    # Command injection sanitization
    TaintSanitizer("shlex.quote", "shlex.quote(", Language.PYTHON, "Shell quoting"),
    TaintSanitizer("shlex.split", "shlex.split(", Language.PYTHON, "Safe shell argument splitting"),
    # SQL sanitization
    TaintSanitizer("parameterized_query", "%(", Language.PYTHON, "Parameterized SQL (format)"),
    TaintSanitizer("parameterized_qmark", "?", Language.PYTHON, "Parameterized SQL (qmark)"),
    TaintSanitizer("parameterized_dollar", "$1", Language.PYTHON, "Parameterized SQL (positional)"),
    TaintSanitizer("parameterized_named", ":param", Language.PYTHON, "Parameterized SQL (named)"),
    # URL/path sanitization
    TaintSanitizer("urllib.parse.quote", "urllib.parse.quote(", Language.PYTHON, "URL encoding"),
    TaintSanitizer("urllib.parse.urlencode", "urllib.parse.urlencode(", Language.PYTHON, "URL parameter encoding"),
    TaintSanitizer("os.path.basename", "os.path.basename(", Language.PYTHON, "Path traversal prevention"),
    TaintSanitizer("os.path.normpath", "os.path.normpath(", Language.PYTHON, "Path normalization"),
    TaintSanitizer("pathlib.PurePath", "PurePath(", Language.PYTHON, "Safe path handling"),
    # Encoding
    TaintSanitizer("json.dumps", "json.dumps(", Language.PYTHON, "JSON serialization"),
    TaintSanitizer("base64.b64encode", "base64.b64encode(", Language.PYTHON, "Base64 encoding"),
    # Validation
    TaintSanitizer("re.match", "re.match(", Language.PYTHON, "Regex validation"),
    TaintSanitizer("re.fullmatch", "re.fullmatch(", Language.PYTHON, "Full regex validation"),
    TaintSanitizer("validator", "validate(", Language.PYTHON, "Generic validator"),
)

JAVASCRIPT_SANITIZERS: tuple[TaintSanitizer, ...] = (
    # Type casting
    TaintSanitizer("parseInt", "parseInt(", Language.JAVASCRIPT, "Integer parse"),
    TaintSanitizer("parseFloat", "parseFloat(", Language.JAVASCRIPT, "Float parse"),
    TaintSanitizer("Number", "Number(", Language.JAVASCRIPT, "Number cast"),
    TaintSanitizer("Boolean", "Boolean(", Language.JAVASCRIPT, "Boolean cast"),
    # HTML/XSS sanitization
    TaintSanitizer("DOMPurify.sanitize", "DOMPurify.sanitize(", Language.JAVASCRIPT, "DOM sanitizer"),
    TaintSanitizer("xss", "xss(", Language.JAVASCRIPT, "xss npm package"),
    TaintSanitizer("sanitize-html", "sanitizeHtml(", Language.JAVASCRIPT, "sanitize-html package"),
    TaintSanitizer("escape", "escape(", Language.JAVASCRIPT, "HTML escape"),
    TaintSanitizer("he.encode", "he.encode(", Language.JAVASCRIPT, "he HTML entities"),
    # URL encoding
    TaintSanitizer("encodeURIComponent", "encodeURIComponent(", Language.JAVASCRIPT, "URI component encode"),
    TaintSanitizer("encodeURI", "encodeURI(", Language.JAVASCRIPT, "URI encode"),
    # Path sanitization
    TaintSanitizer("path.basename", "path.basename(", Language.JAVASCRIPT, "Path basename extraction"),
    TaintSanitizer("path.normalize", "path.normalize(", Language.JAVASCRIPT, "Path normalization"),
    # JSON/encoding
    TaintSanitizer("JSON.stringify", "JSON.stringify(", Language.JAVASCRIPT, "JSON serialization"),
    # SQL parameterization
    TaintSanitizer("prepared_statement", "?", Language.JAVASCRIPT, "SQL placeholder"),
    # Validation
    TaintSanitizer("validator.escape", "validator.escape(", Language.JAVASCRIPT, "validator.js escape"),
    TaintSanitizer("Joi.validate", "Joi.validate(", Language.JAVASCRIPT, "Joi schema validation"),
    TaintSanitizer("zod.parse", ".parse(", Language.JAVASCRIPT, "Zod schema validation"),
)

GO_SANITIZERS: tuple[TaintSanitizer, ...] = (
    TaintSanitizer("strconv.Atoi", "strconv.Atoi(", Language.GO, "String to int conversion"),
    TaintSanitizer("strconv.ParseInt", "strconv.ParseInt(", Language.GO, "String to int64 conversion"),
    TaintSanitizer("strconv.ParseFloat", "strconv.ParseFloat(", Language.GO, "String to float conversion"),
    TaintSanitizer("html.EscapeString", "html.EscapeString(", Language.GO, "HTML escape"),
    TaintSanitizer("url.QueryEscape", "url.QueryEscape(", Language.GO, "URL query escape"),
    TaintSanitizer("filepath.Clean", "filepath.Clean(", Language.GO, "File path sanitization"),
)

JAVA_SANITIZERS: tuple[TaintSanitizer, ...] = (
    # Type casting
    TaintSanitizer("Integer.parseInt", "Integer.parseInt(", Language.JAVA, "String to int"),
    TaintSanitizer("Integer.valueOf", "Integer.valueOf(", Language.JAVA, "String to Integer"),
    TaintSanitizer("Long.parseLong", "Long.parseLong(", Language.JAVA, "String to long"),
    TaintSanitizer("Double.parseDouble", "Double.parseDouble(", Language.JAVA, "String to double"),
    TaintSanitizer("UUID.fromString", "UUID.fromString(", Language.JAVA, "UUID validation/cast"),
    # HTML/XSS sanitization
    TaintSanitizer("HtmlUtils.htmlEscape", "HtmlUtils.htmlEscape(", Language.JAVA, "Spring HTML escape"),
    TaintSanitizer("StringEscapeUtils.escapeHtml4", "StringEscapeUtils.escapeHtml4(", Language.JAVA, "Apache Commons HTML escape"),
    TaintSanitizer("Jsoup.clean", "Jsoup.clean(", Language.JAVA, "Jsoup HTML sanitizer"),
    TaintSanitizer("ESAPI.encoder", "ESAPI.encoder().encodeForHTML(", Language.JAVA, "OWASP ESAPI HTML encoder"),
    # SQL parameterization
    TaintSanitizer("PreparedStatement", "preparedStatement.set", Language.JAVA, "JDBC parameterized query"),
    TaintSanitizer("CriteriaBuilder", "criteriaBuilder.", Language.JAVA, "JPA Criteria API (safe by design)"),
    # URL/path sanitization
    TaintSanitizer("URLEncoder.encode", "URLEncoder.encode(", Language.JAVA, "URL encoding"),
    TaintSanitizer("Paths.get.normalize", ".normalize(", Language.JAVA, "NIO path normalization"),
    # Validation
    TaintSanitizer("Pattern.matches", "Pattern.matches(", Language.JAVA, "Regex validation"),
    TaintSanitizer("StringUtils.isNumeric", "StringUtils.isNumeric(", Language.JAVA, "Apache Commons numeric check"),
    TaintSanitizer("@Valid", "@Valid", Language.JAVA, "Bean Validation annotation"),
    TaintSanitizer("@Validated", "@Validated", Language.JAVA, "Spring validation annotation"),
)

TAINT_SANITIZERS: dict[Language, tuple[TaintSanitizer, ...]] = {
    Language.PYTHON: PYTHON_SANITIZERS,
    Language.JAVASCRIPT: JAVASCRIPT_SANITIZERS,
    Language.TYPESCRIPT: JAVASCRIPT_SANITIZERS,
    Language.GO: GO_SANITIZERS,
    Language.JAVA: JAVA_SANITIZERS,
}
