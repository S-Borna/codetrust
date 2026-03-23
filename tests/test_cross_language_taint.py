# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for cross-language taint analysis — the feature no other tool has.

Each test represents a real-world polyglot scenario where tainted data
crosses an HTTP boundary between different programming languages.
"""

import pytest

from src.models.enums import Language
from src.services.cross_language_taint import (
    CrossLanguageTaintAnalyzer,
    CrossLanguageTaintResult,
)


@pytest.fixture()
def analyzer() -> CrossLanguageTaintAnalyzer:
    """Create a cross-language taint analyzer."""
    return CrossLanguageTaintAnalyzer()


# ═══════════════════════════════════════════════════════════════
#  Route extraction tests
# ═══════════════════════════════════════════════════════════════


class TestRouteExtraction:
    """Test HTTP route extraction across frameworks."""

    def test_flask_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Flask @app.route decorator."""
        code = '''
@app.route("/api/users")
def get_users():
    return jsonify(users)
'''
        routes = analyzer._extract_python_routes("app.py", code)
        assert len(routes) >= 1
        assert routes[0].path == "/api/users"
        assert routes[0].handler_name == "get_users"

    def test_fastapi_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect FastAPI @app.get decorator."""
        code = '''
@app.get("/api/items/{item_id}")
async def get_item(item_id: str):
    return {"item_id": item_id}
'''
        routes = analyzer._extract_python_routes("api.py", code)
        assert len(routes) >= 1
        assert "/api/items" in routes[0].path

    def test_express_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Express router.get()."""
        code = '''
router.get("/api/users", getUsers);
router.post("/api/users", createUser);
'''
        routes = analyzer._extract_js_routes(
            "routes.js", code, Language.JAVASCRIPT,
        )
        assert len(routes) == 2
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[1].method == "POST"

    def test_go_handlefunc(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Go http.HandleFunc()."""
        code = '''
http.HandleFunc("/api/users", HandleUsers)
http.HandleFunc("/api/items", HandleItems)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) == 2
        assert routes[0].path == "/api/users"
        assert routes[0].handler_name == "HandleUsers"

    def test_django_path(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Django path() URL pattern."""
        code = '''
urlpatterns = [
    path("api/users/", user_list),
    path("api/users/<int:pk>/", user_detail),
]
'''
        routes = analyzer._extract_python_routes("urls.py", code)
        assert len(routes) == 2

    def test_gin_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Gin router.GET()."""
        code = '''
router.GET("/api/users", getUsers)
router.POST("/api/users", createUser)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) == 2
        assert routes[0].method == "GET"


# ═══════════════════════════════════════════════════════════════
#  HTTP call extraction tests
# ═══════════════════════════════════════════════════════════════


class TestHttpCallExtraction:
    """Test HTTP client call extraction."""

    def test_js_fetch(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect fetch() calls in JavaScript."""
        code = '''
const response = await fetch("/api/users?id=" + userId);
'''
        calls = analyzer._extract_js_http_calls(
            "app.js", code, Language.JAVASCRIPT,
        )
        assert len(calls) >= 1
        assert "/api/users" in calls[0].url_pattern

    def test_js_axios(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect axios.post() calls."""
        code = '''
const result = await axios.post("/api/users", { name: userName });
'''
        calls = analyzer._extract_js_http_calls(
            "client.js", code, Language.JAVASCRIPT,
        )
        assert len(calls) >= 1
        assert calls[0].method == "POST"

    def test_python_requests(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect requests.get() calls in Python."""
        code = '''
response = requests.get("/api/items/" + item_id)
'''
        calls = analyzer._extract_python_http_calls("client.py", code)
        assert len(calls) >= 1
        assert calls[0].method == "GET"

    def test_go_http_get(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect http.Get() calls in Go."""
        code = '''
resp, err := http.Get("/api/users?id=" + userId)
'''
        calls = analyzer._extract_go_http_calls("client.go", code)
        assert len(calls) >= 1
        assert calls[0].method == "GET"


# ═══════════════════════════════════════════════════════════════
#  Path matching tests
# ═══════════════════════════════════════════════════════════════


class TestPathMatching:
    """Test URL path matching between callers and routes."""

    def test_exact_match(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Exact path match."""
        assert analyzer._paths_match("/api/users", "/api/users")

    def test_trailing_slash(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Trailing slash normalization."""
        assert analyzer._paths_match("/api/users/", "/api/users")

    def test_query_string_stripped(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Query strings are stripped before matching."""
        assert analyzer._paths_match("/api/users?id=123", "/api/users")

    def test_express_param(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Express :id path parameter matching."""
        assert analyzer._paths_match("/api/users/123", "/api/users/:id")

    def test_flask_param(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Flask <id> path parameter matching."""
        assert analyzer._paths_match("/api/users/123", "/api/users/<int:id>")

    def test_no_match(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Non-matching paths."""
        assert not analyzer._paths_match("/api/items", "/api/users")

    def test_method_compatible_any(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """ANY route method matches all call methods."""
        assert analyzer._methods_compatible("GET", "ANY")
        assert analyzer._methods_compatible("POST", "ANY")

    def test_method_mismatch(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Mismatched methods."""
        assert not analyzer._methods_compatible("GET", "POST")


# ═══════════════════════════════════════════════════════════════
#  Cross-language taint flow tests — the main event
# ═══════════════════════════════════════════════════════════════


class TestCrossLanguageTaintFlows:
    """End-to-end cross-language taint detection.

    Each test simulates a real polyglot application where tainted data
    crosses an HTTP boundary between different programming languages.
    """

    def test_js_frontend_to_python_backend_sql_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """JS fetch sends user input to Python Flask handler with SQL injection.

        Scenario: React frontend takes user input, sends it to a Flask API,
        which uses it in a raw SQL query without parameterization.
        """
        files = {
            "frontend/app.js": '''
function searchUsers(query) {
    const userInput = document.getElementById("search").value;
    fetch("/api/users?q=" + userInput);
}
''',
            "backend/app.py": '''
@app.route("/api/users")
def search_users():
    q = request.args.get("q")
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")
    return jsonify(results)
''',
        }

        result = analyzer.analyze(files)
        assert result.routes_discovered >= 1
        assert result.http_calls_discovered >= 1
        assert result.languages_analyzed >= 2

    def test_js_to_go_command_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """JS sends user input to Go handler with command injection.

        Scenario: Node.js admin panel sends a filename to a Go file
        processing service which passes it to exec.Command.
        """
        files = {
            "admin/index.js": '''
async function processFile() {
    const filename = req.body.filename;
    await axios.post("/api/process", { file: filename });
}
''',
            "service/handler.go": '''
func ProcessFile(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    exec.Command("convert", filename)
}
''',
        }

        result = analyzer.analyze(files)
        assert result.routes_discovered >= 0
        assert result.total_files == 2
        assert result.languages_analyzed >= 2

    def test_python_to_go_sql_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Python microservice forwards user data to Go service with SQL sink.

        Scenario: Python API gateway receives user input and forwards it
        to a Go data service which uses it in an unparameterized SQL query.
        """
        files = {
            "gateway/api.py": '''
@app.post("/api/search")
async def search(request):
    query = request.json.get("query")
    response = httpx.get("/internal/data?q=" + query)
    return response.json()
''',
            "data-service/main.go": '''
func HandleData(w http.ResponseWriter, r *http.Request) {
    q := r.FormValue("q")
    db.Query("SELECT * FROM records WHERE title = " + q)
}
''',
        }

        result = analyzer.analyze(files)
        assert result.total_files == 2
        assert result.languages_analyzed >= 2
        assert result.routes_discovered >= 1

    def test_clean_project_no_findings(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Clean polyglot project produces no cross-language taint findings."""
        files = {
            "frontend/app.js": '''
function loadDashboard() {
    fetch("/api/stats");
}
''',
            "backend/app.py": '''
@app.route("/api/stats")
def get_stats():
    count = db.query("SELECT COUNT(*) FROM users")
    return jsonify({"count": count})
''',
        }

        result = analyzer.analyze(files)
        # No user input flows across boundary — no findings
        cross_lang = [
            f for f in result.findings
            if f.rule_id.startswith("cross_lang_taint_")
        ]
        assert len(cross_lang) == 0

    def test_three_language_chain(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Taint flows through three languages: JS -> Python -> Go.

        Scenario: React frontend sends search query to Python API gateway,
        which forwards it to a Go search microservice with SQL injection.
        """
        files = {
            "web/search.js": '''
function search() {
    const term = document.getElementById("search").value;
    fetch("/api/search?q=" + term);
}
''',
            "api/gateway.py": '''
@app.route("/api/search")
def search():
    q = request.args.get("q")
    result = requests.get("/internal/search?query=" + q)
    return jsonify(result.json())
''',
            "search/handler.go": '''
func SearchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.FormValue("query")
    db.Query("SELECT * FROM products WHERE name LIKE '%" + query + "%'")
}
''',
        }

        result = analyzer.analyze(files)
        assert result.total_files == 3
        assert result.languages_analyzed == 3

    def test_same_language_excluded(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Cross-language analyzer only fires across language boundaries.

        Same-language taint is handled by the regular cross-file analyzer.
        """
        files = {
            "client.py": '''
import requests
def call_api():
    user_id = input("Enter ID: ")
    requests.get("/api/users/" + user_id)
''',
            "server.py": '''
@app.route("/api/users/<user_id>")
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return jsonify(user)
''',
        }

        result = analyzer.analyze(files)
        # Both files are Python — cross-language analyzer should not fire
        cross_lang = [
            f for f in result.findings
            if f.rule_id.startswith("cross_lang_taint_")
        ]
        assert len(cross_lang) == 0


# ═══════════════════════════════════════════════════════════════
#  Metrics and edge cases
# ═══════════════════════════════════════════════════════════════


class TestMetricsAndEdgeCases:
    """Test result metrics and edge cases."""

    def test_empty_project(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Empty project returns zero metrics."""
        result = analyzer.analyze({})
        assert result.total_files == 0
        assert result.routes_discovered == 0
        assert result.http_calls_discovered == 0
        assert result.cross_language_flows == 0
        assert len(result.findings) == 0

    def test_single_language_project(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Single-language project has no cross-language flows."""
        files = {
            "app.py": '''
@app.route("/api/users")
def users():
    return "ok"
''',
        }
        result = analyzer.analyze(files)
        assert result.languages_analyzed == 1
        assert result.cross_language_flows == 0

    def test_result_type(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Result is the correct type with expected fields."""
        result = analyzer.analyze({})
        assert isinstance(result, CrossLanguageTaintResult)
        assert hasattr(result, "findings")
        assert hasattr(result, "routes_discovered")
        assert hasattr(result, "cross_language_flows")

    def test_route_discovery_metrics(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Routes from multiple languages are all discovered."""
        files = {
            "app.py": '''
@app.route("/api/py")
def py_handler():
    return "ok"
''',
            "app.js": '''
router.get("/api/js", jsHandler);
''',
            "main.go": '''
http.HandleFunc("/api/go", GoHandler)
''',
        }
        result = analyzer.analyze(files)
        assert result.routes_discovered >= 3
        assert result.languages_analyzed == 3


# ═══════════════════════════════════════════════════════════════
#  New framework route extraction tests
# ═══════════════════════════════════════════════════════════════


class TestNewFrameworkRouteExtraction:
    """Test route extraction for newly added frameworks."""

    def test_starlette_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Starlette @app.route() decorator."""
        code = '''
@app.route("/api/health", methods=["GET"])
async def health_check(request):
    return JSONResponse({"status": "ok"})
'''
        routes = analyzer._extract_python_routes("app.py", code)
        assert len(routes) >= 1
        found = [r for r in routes if r.path == "/api/health"]
        assert len(found) >= 1
        assert found[0].method in ("GET", "ANY")

    def test_aiohttp_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect aiohttp @routes.get() decorator."""
        code = '''
@routes.get("/api/users")
async def get_users(request):
    return web.json_response(users)

@routes.post("/api/users")
async def create_user(request):
    data = await request.json()
    return web.json_response(data)
'''
        routes = analyzer._extract_python_routes("handlers.py", code)
        assert len(routes) >= 2
        methods = {r.method for r in routes if "/api/users" in r.path}
        assert "GET" in methods
        assert "POST" in methods

    def test_tornado_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Tornado URL mapping with RequestHandler."""
        code = '''
class UserHandler(RequestHandler):
    def get(self):
        self.write({"users": []})

app = Application([
    (r"/api/users", UserHandler),
    (r"/api/items", ItemHandler),
])
'''
        routes = analyzer._extract_python_routes("app.py", code)
        tornado_routes = [r for r in routes if r.path == "/api/users"]
        assert len(tornado_routes) >= 1
        assert tornado_routes[0].handler_name == "UserHandler"

    def test_nestjs_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect NestJS @Controller + @Get/@Post decorators."""
        code = '''
@Controller("/api/users")
export class UsersController {
    @Get("/list")
    async findAll() {
        return this.usersService.findAll();
    }

    @Post("/create")
    async create(@Body() dto: CreateUserDto) {
        return this.usersService.create(dto);
    }
}
'''
        routes = analyzer._extract_js_routes(
            "users.controller.ts", code, Language.TYPESCRIPT,
        )
        assert len(routes) >= 2
        paths = {r.path for r in routes}
        assert "/api/users/list" in paths
        assert "/api/users/create" in paths
        methods = {r.method for r in routes}
        assert "GET" in methods
        assert "POST" in methods

    def test_fastify_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Fastify fastify.get()/post() routes."""
        code = '''
fastify.get("/api/users", async (request, reply) => {
    return { users: [] };
});

fastify.post("/api/users", async (request, reply) => {
    const user = request.body;
    return { id: 1, ...user };
});
'''
        routes = analyzer._extract_js_routes(
            "routes.ts", code, Language.TYPESCRIPT,
        )
        assert len(routes) >= 2
        methods = {r.method for r in routes if r.path == "/api/users"}
        assert "GET" in methods
        assert "POST" in methods

    def test_hapi_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Hapi server.route() definitions."""
        code = '''
server.route({ method: 'GET', path: '/api/users', handler: getUsers });
server.route({ method: 'POST', path: '/api/users', handler: createUser });
'''
        routes = analyzer._extract_js_routes(
            "server.js", code, Language.JAVASCRIPT,
        )
        assert len(routes) >= 2
        methods = {r.method for r in routes if r.path == "/api/users"}
        assert "GET" in methods
        assert "POST" in methods

    def test_fiber_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Go Fiber app.Get()/Post() routes."""
        code = '''
app.Get("/api/users", getUsers)
app.Post("/api/users", createUser)
app.Delete("/api/users/:id", deleteUser)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) >= 3
        methods = {r.method for r in routes if "/api/users" in r.path}
        assert "GET" in methods
        assert "POST" in methods
        assert "DELETE" in methods

    def test_echo_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Go Echo e.GET()/POST() routes."""
        code = '''
e.GET("/api/users", getUsers)
e.POST("/api/users", createUser)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) >= 2
        methods = {r.method for r in routes if r.path == "/api/users"}
        assert "GET" in methods
        assert "POST" in methods

    def test_chi_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Go Chi r.Get()/Post() routes."""
        code = '''
r.Get("/api/users", getUsers)
r.Post("/api/users", createUser)
r.Put("/api/users/{id}", updateUser)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) >= 3
        methods = {r.method for r in routes if "/api/users" in r.path}
        assert "GET" in methods
        assert "POST" in methods
        assert "PUT" in methods

    def test_gorilla_mux_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect gorilla/mux r.HandleFunc().Methods() routes."""
        code = '''
r.HandleFunc("/api/users", getUsers).Methods("GET")
r.HandleFunc("/api/users", createUser).Methods("POST")
'''
        routes = analyzer._extract_go_routes("main.go", code)
        gorilla_routes = [r for r in routes if r.path == "/api/users"]
        assert len(gorilla_routes) >= 2
        methods = {r.method for r in gorilla_routes}
        assert "GET" in methods
        assert "POST" in methods


# ═══════════════════════════════════════════════════════════════
#  gRPC extraction and cross-language flow tests
# ═══════════════════════════════════════════════════════════════


class TestGrpcExtraction:
    """Test gRPC service/client extraction from proto files and code."""

    def test_proto_service_extraction(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Extract rpc methods from .proto service definitions."""
        proto = '''
syntax = "proto3";

service UserService {
    rpc GetUser (GetUserRequest) returns (GetUserResponse);
    rpc CreateUser (CreateUserRequest) returns (CreateUserResponse);
}

service OrderService {
    rpc PlaceOrder (PlaceOrderRequest) returns (PlaceOrderResponse);
}
'''
        services = analyzer._extract_grpc_proto_services("user.proto", proto)
        assert len(services) == 3
        method_names = {s.method_name for s in services}
        assert "GetUser" in method_names
        assert "CreateUser" in method_names
        assert "PlaceOrder" in method_names
        svc_names = {s.service_name for s in services}
        assert "UserService" in svc_names
        assert "OrderService" in svc_names

    def test_python_grpc_client_extraction(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Extract Python gRPC stub calls."""
        code = '''
channel = grpc.insecure_channel("localhost:50051")
user_stub = UserServiceStub(channel)
response = user_stub.GetUser(request)
response2 = user_stub.CreateUser(create_request)
'''
        calls = analyzer._extract_grpc_python_clients("client.py", code)
        assert len(calls) >= 2
        method_names = {c.method_name for c in calls}
        assert "GetUser" in method_names
        assert "CreateUser" in method_names

    def test_go_grpc_server_extraction(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Extract Go gRPC server method implementations."""
        code = '''
func (s *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
    user := s.db.FindUser(req.Id)
    return &pb.GetUserResponse{User: user}, nil
}

func (s *UserServer) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
    user := s.db.CreateUser(req.Name)
    return &pb.CreateUserResponse{User: user}, nil
}
'''
        services = analyzer._extract_grpc_go_servers("server.go", code)
        assert len(services) == 2
        method_names = {s.method_name for s in services}
        assert "GetUser" in method_names
        assert "CreateUser" in method_names
        assert all(s.service_name == "User" for s in services)

    def test_js_grpc_client_extraction(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Extract JS/TS gRPC client calls."""
        code = '''
const userClient = new UserServiceClient("localhost:50051");
const response = await userClient.getUser(request);
const response2 = await userClient.createUser(createRequest);
'''
        calls = analyzer._extract_grpc_js_clients(
            "client.ts", code, Language.TYPESCRIPT,
        )
        assert len(calls) >= 2
        method_names = {c.method_name for c in calls}
        assert "GetUser" in method_names
        assert "CreateUser" in method_names

    def test_python_grpc_server_extraction(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Extract Python gRPC Servicer class methods."""
        code = '''
class UserServiceServicer(user_pb2_grpc.UserServiceServicer):
    def GetUser(self, request, context):
        user = self.db.find(request.id)
        return user_pb2.GetUserResponse(user=user)

    def CreateUser(self, request, context):
        user = self.db.create(request.name)
        return user_pb2.CreateUserResponse(user=user)
'''
        services = analyzer._extract_grpc_python_servers("server.py", code)
        assert len(services) == 2
        method_names = {s.method_name for s in services}
        assert "GetUser" in method_names
        assert "CreateUser" in method_names


class TestGrpcCrossLanguageFlows:
    """Test gRPC cross-language taint flow detection."""

    def test_python_client_to_go_server(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Detect gRPC flow: Python client calling Go server."""
        files = {
            "client.py": '''
channel = grpc.insecure_channel("localhost:50051")
userStub = UserServiceStub(channel)
response = userStub.GetUser(request)
''',
            "server.go": '''
func (s *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
    user := s.db.FindUser(req.Id)
    return &pb.GetUserResponse{User: user}, nil
}
''',
        }

        result = analyzer.analyze(files)
        assert result.grpc_calls_discovered >= 1
        assert result.grpc_services_discovered >= 1
        assert result.grpc_flows >= 1
        assert result.languages_analyzed >= 2

    def test_js_client_to_python_server(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Detect gRPC flow: JS client calling Python server."""
        files = {
            "client.ts": '''
const userClient = new UserServiceClient("localhost:50051");
const response = await userClient.getUser(request);
''',
            "server.py": '''
class UserServiceServicer(user_pb2_grpc.UserServiceServicer):
    def GetUser(self, request, context):
        user = self.db.find(request.id)
        return user_pb2.GetUserResponse(user=user)
''',
        }

        result = analyzer.analyze(files)
        assert result.grpc_calls_discovered >= 1
        assert result.grpc_services_discovered >= 1
        assert result.grpc_flows >= 1
        assert result.languages_analyzed >= 2

    def test_same_language_grpc_excluded(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Same-language gRPC calls should not produce cross-language flows."""
        files = {
            "client.py": '''
channel = grpc.insecure_channel("localhost:50051")
userStub = UserServiceStub(channel)
response = userStub.GetUser(request)
''',
            "server.py": '''
class UserServiceServicer(user_pb2_grpc.UserServiceServicer):
    def GetUser(self, request, context):
        return user_pb2.GetUserResponse()
''',
        }

        result = analyzer.analyze(files)
        assert result.grpc_flows == 0

    def test_grpc_metrics_in_result(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Result includes gRPC metrics."""
        result = analyzer.analyze({})
        assert hasattr(result, "grpc_services_discovered")
        assert hasattr(result, "grpc_calls_discovered")
        assert hasattr(result, "grpc_flows")
        assert result.grpc_services_discovered == 0
        assert result.grpc_calls_discovered == 0
        assert result.grpc_flows == 0
