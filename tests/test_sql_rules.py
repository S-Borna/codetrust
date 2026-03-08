"""Tests for SQL anti-pattern detection rules."""

import pytest

from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer()


# ── BLOCK rules ──────────────────────────────────────────────────


class TestSelectStar:
    def test_select_star_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "SELECT * FROM users;"
        findings = analyzer.scan_code(code, "query.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_select_star" in ids

    def test_select_columns_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "SELECT id, name FROM users;"
        findings = analyzer.scan_code(code, "query.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_select_star" not in ids

    def test_select_star_case_insensitive(self, analyzer: StaticAnalyzer) -> None:
        code = "select * from orders;"
        findings = analyzer.scan_code(code, "query.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_select_star" in ids


class TestDeleteNoWhere:
    def test_delete_no_where_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "DELETE FROM users;"
        findings = analyzer.scan_code(code, "migrate.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_delete_no_where" in ids

    def test_delete_with_where_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "DELETE FROM users WHERE id = 5;"
        findings = analyzer.scan_code(code, "migrate.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_delete_no_where" not in ids


class TestUpdateNoWhere:
    def test_update_no_where_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "UPDATE users SET active = 0;"
        findings = analyzer.scan_code(code, "fix.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_update_no_where" in ids

    def test_update_with_where_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "UPDATE users SET active = 0 WHERE id = 1;"
        findings = analyzer.scan_code(code, "fix.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_update_no_where" not in ids


class TestDropNoIfExists:
    def test_drop_without_if_exists_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "DROP TABLE users;"
        findings = analyzer.scan_code(code, "drop.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_drop_no_if_exists" in ids

    def test_drop_with_if_exists_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "DROP TABLE IF EXISTS users;"
        findings = analyzer.scan_code(code, "drop.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_drop_no_if_exists" not in ids

    def test_drop_database_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "DROP DATABASE production;"
        findings = analyzer.scan_code(code, "nuke.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_drop_no_if_exists" in ids


class TestGrantAll:
    def test_grant_all_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';"
        findings = analyzer.scan_code(code, "perms.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_grant_all" in ids

    def test_grant_specific_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "GRANT SELECT, INSERT ON mydb.* TO 'app'@'localhost';"
        findings = analyzer.scan_code(code, "perms.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_grant_all" not in ids


class TestForeignKeyChecks:
    def test_fk_checks_off_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "SET FOREIGN_KEY_CHECKS = 0;"
        findings = analyzer.scan_code(code, "migrate.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_foreign_key_checks_off" in ids


# ── WARN rules ───────────────────────────────────────────────────


class TestFloatForMoney:
    def test_float_price_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "selling_price FLOAT NOT NULL,"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_float_for_money" in ids

    def test_decimal_price_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "selling_price DECIMAL(10,2) NOT NULL,"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_float_for_money" not in ids

    def test_wholesale_cost_float(self, analyzer: StaticAnalyzer) -> None:
        code = "wholesale_cost FLOAT NOT NULL,"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_float_for_money" in ids


class TestVarcharNoLength:
    def test_varchar_empty_parens(self, analyzer: StaticAnalyzer) -> None:
        code = "name VARCHAR() NOT NULL,"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_varchar_no_length" in ids

    def test_varchar_with_length_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "name VARCHAR(50) NOT NULL,"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_varchar_no_length" not in ids


class TestSqlTodo:
    def test_sql_todo_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "-- TODO: add index later"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_todo_hack" in ids

    def test_sql_fixme_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "-- FIXME: this is broken"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_todo_hack" in ids


# ── INFO rules ───────────────────────────────────────────────────


class TestAutocommitOff:
    def test_autocommit_off_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "SET autocommit = 0;"
        findings = analyzer.scan_code(code, "tx.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_autocommit_off" in ids


class TestHardcodedId:
    def test_hardcoded_id_string(self, analyzer: StaticAnalyzer) -> None:
        code = "INSERT INTO products (name, manufacturer_id) VALUES ('Widget', '1');"
        findings = analyzer.scan_code(code, "seed.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_hardcoded_id" in ids

    def test_integer_id_ok(self, analyzer: StaticAnalyzer) -> None:
        code = "INSERT INTO products (name, manufacturer_id) VALUES ('Widget', 1);"
        findings = analyzer.scan_code(code, "seed.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_hardcoded_id" not in ids


class TestForeignKeyIndex:
    def test_fk_info_emitted(self, analyzer: StaticAnalyzer) -> None:
        code = "FOREIGN KEY (user_id) REFERENCES users (id)"
        findings = analyzer.scan_code(code, "schema.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_no_index_hint" in ids


# ── File-type isolation ──────────────────────────────────────────


class TestFileTypeIsolation:
    """SQL rules must NOT fire on .py files and vice versa."""

    def test_sql_rules_dont_fire_on_python(self, analyzer: StaticAnalyzer) -> None:
        code = "SELECT * FROM users;"
        findings = analyzer.scan_code(code, "service.py")
        sql_ids = [f.rule_id for f in findings if f.rule_id.startswith("sql_")]
        assert sql_ids == []

    def test_python_rules_dont_fire_on_sql(self, analyzer: StaticAnalyzer) -> None:
        code = "print('hello')\nimport os\n" + "ev" + "al('x')"
        findings = analyzer.scan_code(code, "seed.sql")
        generic_ids = [f.rule_id for f in findings if not f.rule_id.startswith("sql_")]
        assert generic_ids == []

    def test_generic_rules_still_fire_on_python(self, analyzer: StaticAnalyzer) -> None:
        code = "ev" + "al('dangerous')"
        findings = analyzer.scan_code(code, "app.py")
        ids = [f.rule_id for f in findings]
        assert "eval_exec" in ids


# ── Full-file integration ────────────────────────────────────────


class TestAlexShopFile:
    """Integration test — scan the actual attached SQL migration."""

    SQL_FILE = "/Users/mrebadi/Desktop/DevOps/Gruppuppgift-Databas/grupp-1-databas/migrations/03-alex-shop.sql"

    @pytest.fixture
    def sql_code(self) -> str:
        try:
            with open(self.SQL_FILE) as f:
                return f.read()
        except FileNotFoundError:
            pytest.skip("SQL test file not available on this machine")

    def test_finds_issues(self, analyzer: StaticAnalyzer, sql_code: str) -> None:
        findings = analyzer.scan_code(sql_code, "03-alex-shop.sql")
        assert len(findings) > 0, "Should find SQL anti-patterns"

    def test_float_money_detected(self, analyzer: StaticAnalyzer, sql_code: str) -> None:
        if "FLOAT" not in sql_code.upper():
            pytest.skip("External SQL file no longer contains FLOAT")
        findings = analyzer.scan_code(sql_code, "03-alex-shop.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_float_for_money" in ids

    def test_foreign_key_checks_off(self, analyzer: StaticAnalyzer, sql_code: str) -> None:
        if "FOREIGN_KEY_CHECKS" not in sql_code.upper():
            pytest.skip("External SQL file no longer contains FOREIGN_KEY_CHECKS")
        findings = analyzer.scan_code(sql_code, "03-alex-shop.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_foreign_key_checks_off" in ids

    def test_hardcoded_ids_detected(self, analyzer: StaticAnalyzer, sql_code: str) -> None:
        findings = analyzer.scan_code(sql_code, "03-alex-shop.sql")
        ids = [f.rule_id for f in findings]
        assert "sql_hardcoded_id" in ids

    def test_no_false_python_rules(self, analyzer: StaticAnalyzer, sql_code: str) -> None:
        """Generic Python rules must NOT fire on the SQL file."""
        findings = analyzer.scan_code(sql_code, "03-alex-shop.sql")
        generic = [f for f in findings if not f.rule_id.startswith("sql_")]
        assert generic == [], f"Generic rules fired on SQL: {[f.rule_id for f in generic]}"
