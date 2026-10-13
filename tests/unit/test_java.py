from sentinela.engine.scanner import ScanOptions, scan_source

OPTS = ScanOptions(use_bandit=False)

CONTROLLER = """
import java.sql.*;
public class C {
    @GetMapping("/x")
    public void x(@RequestParam String id, HttpServletRequest request) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM t WHERE id = " + id;
        stmt.executeQuery(sql);
        int n = Integer.parseInt(request.getParameter("n"));
        Runtime.getRuntime().exec("job " + n);
        Runtime.getRuntime().exec(request.getParameter("cmd"));
    }
}
"""


def _rules(source: str) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for finding in scan_source("C.java", source, "java", OPTS):
        found.setdefault(finding.rule_id, []).append(finding.line)
    return found


def test_annotated_parameter_is_a_source_and_types_resolve_receivers():
    rules = _rules(CONTROLLER)
    assert rules["java.taint.sql-injection"] == [8]


def test_integer_parse_sanitizes_but_raw_parameter_does_not():
    rules = _rules(CONTROLLER)
    assert rules["java.taint.command-injection"] == [11]
    assert rules["java.command.runtime-exec"] == [10]  # padrão sozinho na linha sanitizada


def test_weak_crypto_rules():
    source = 'class K { void k() throws Exception { MessageDigest.getInstance("SHA-1"); Cipher.getInstance("AES/ECB/PKCS5Padding"); Cipher.getInstance("AES/GCM/NoPadding"); } }'
    assert _rules(source) == {"java.crypto.weak-hash": [1], "java.crypto.weak-cipher": [1]}
