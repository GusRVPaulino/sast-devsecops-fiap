import pytest

from sentinela.engine.scanner import ScanOptions, scan_source
from sentinela.engine.secrets import looks_like_secret, provider_token

OPTS = ScanOptions(use_bandit=False)


@pytest.mark.parametrize(
    ("name", "value", "expected"),
    [
        ("DB_PASSWORD", "Pg#Prod2026!xq", True),
        ("apiKey", "a8f5f167f44f4964e6c9", True),
        ("PASSWORD_FIELD", "password", False),
        ("password_hint", "Use 8 caracteres ou mais", False),
        ("token", "changeme", False),
        ("token", "${TOKEN}", False),
        ("username", "Pg#Prod2026!xq", False),
    ],
)
def test_named_secret_heuristic(name, value, expected):
    assert looks_like_secret(name, value) is expected


def test_provider_formats():
    assert provider_token("AKIAZ4Q7EXAMPLE2MPLX") == "chave de acesso AWS"
    assert provider_token("postgres://app:S3nh4@db:5432/x") == "URL com senha"
    assert provider_token("hello world") is None


@pytest.mark.parametrize(
    ("path", "language", "source"),
    [
        ("a.py", "python", 'DB_PASSWORD = "Pg#Prod2026!xq"\n'),
        ("a.js", "javascript", 'const dbPassword = "Pg#Prod2026!xq";\n'),
        ("A.java", "java", 'class A { String dbPassword = "Pg#Prod2026!xq"; }\n'),
    ],
)
def test_secret_value_never_leaves_in_any_field(path, language, source):
    (finding,) = scan_source(path, source, language, OPTS)
    assert finding.cwe == "CWE-798"
    for text in (finding.snippet, finding.message, finding.context):
        assert "Pg#Prod2026!xq" not in text


def test_secret_masked_in_context_of_other_findings():
    source = 'import pickle\nAPI_TOKEN = "Tk#9xQ2mLp7vR4"\npickle.loads(x)\n'
    findings = scan_source("a.py", source, "python", OPTS)
    assert len(findings) == 2
    for finding in findings:
        assert "Tk#9xQ2mLp7vR4" not in finding.context


def test_test_files_get_low_severity():
    (finding,) = scan_source("tests/test_login.py", 'password = "Errada#2026!"\n', "python", OPTS)
    assert finding.severity.value == "low"
