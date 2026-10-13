from sentinela.engine.scanner import ScanOptions, scan_source

OPTS = ScanOptions(use_bandit=False)


def _rules(source: str) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for finding in scan_source("app.js", source, "javascript", OPTS):
        found.setdefault(finding.rule_id, []).append(finding.line)
    return found


def test_require_destructuring_resolves_exec():
    source = 'const { exec } = require("child_process");\nexec("ls " + dir);\n'
    assert _rules(source) == {"javascript.command.child-process": [2]}


def test_express_query_to_sql_template():
    source = (
        'app.get("/x", async (req, res) => {\n'
        "  const id = req.query.id;\n"
        "  await db.query(`SELECT * FROM t WHERE id = ${id}`);\n"
        "});\n"
    )
    (finding,) = scan_source("a.js", source, "javascript", OPTS)
    assert finding.rule_id == "javascript.taint.sql-injection"
    assert {e.value for e in finding.engines} == {"rule", "taint"}


def test_dom_xss_member_assignment():
    rules = _rules('el.innerHTML = location.hash;\nel.innerHTML = "<b>fixo</b>";\n')
    assert rules == {"javascript.taint.xss": [1]}


def test_parseint_sanitizes():
    source = 'app.get("/", (req, res) => { const n = parseInt(req.query.n); eval("x" + n); });\n'
    assert "javascript.taint.code-injection" not in _rules(source)


def test_weak_hash_literal_argument():
    assert _rules('const crypto = require("crypto");\ncrypto.createHash("md5");\ncrypto.createHash("sha256");\n') == {
        "javascript.crypto.weak-hash": [2],
    }
