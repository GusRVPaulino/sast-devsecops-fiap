from sentinela.engine.scanner import ScanOptions, scan_source

OPTS = ScanOptions(use_bandit=False)


def _rules(source: str) -> dict[str, list[int]]:
    found: dict[str, list[int]] = {}
    for finding in scan_source("app.py", source, "python", OPTS):
        found.setdefault(finding.rule_id, []).append(finding.line)
    return found


def test_import_alias_is_resolved_for_rules():
    found = _rules("import subprocess as sp\nsp.run(cmd, shell=True)\n")
    assert found == {"python.command.subprocess-shell": [2]}


def test_constant_command_is_not_reported():
    assert _rules('import os\nos.system("ls -la")\nimport subprocess\nsubprocess.run("ls", shell=True)\n') == {}


def test_yaml_safe_loader_is_accepted():
    assert _rules("import yaml\nyaml.load(d, Loader=yaml.SafeLoader)\n") == {}
    assert _rules("import yaml\nyaml.load(d)\n") == {"python.deserialization.yaml-load": [2]}


def test_taint_flows_through_assignments_to_sql():
    source = (
        "from flask import request\n"
        "def view(cursor):\n"
        "    uid = request.args['id']\n"
        "    query = f'SELECT * FROM t WHERE id = {uid}'\n"
        "    cursor.execute(query)\n"
    )
    (finding,) = scan_source("app.py", source, "python", OPTS)
    assert finding.rule_id == "python.taint.sql-injection"
    assert [(s.line, s.kind) for s in finding.taint_path] == [(3, "source"), (4, "propagation"), (5, "sink")]
    assert finding.confidence == "high"


def test_sanitizer_stops_taint():
    source = (
        "import os, shlex\nfrom flask import request\n"
        "def ping():\n"
        "    host = shlex.quote(request.args['h'])\n"
        "    os.system('ping ' + host)\n"
    )
    rules = _rules(source)
    assert "python.taint.command-injection" not in rules
    assert rules == {"python.command.os-system": [5]}  # o padrão ainda avisa, com evidência única


def test_interprocedural_parameter_to_sink():
    source = (
        "import os\nfrom flask import request\n"
        "def run(cmd):\n"
        "    os.system('x ' + cmd)\n"
        "def view():\n"
        "    run(request.form['c'])\n"
    )
    finding = next(f for f in scan_source("a.py", source, "python", OPTS) if f.rule_id.startswith("python.taint"))
    assert finding.line == 4
    assert finding.taint_path[0].line == 6


def test_function_returning_source_is_a_source():
    source = (
        "from flask import request\n"
        "def get_id():\n"
        "    return request.args['id']\n"
        "def view(cursor):\n"
        "    cursor.execute('SELECT ' + get_id())\n"
    )
    rules = _rules(source)
    assert rules["python.taint.sql-injection"] == [5]


def test_pattern_and_taint_on_same_line_merge():
    source = "from flask import request\ndef v():\n    eval(request.args['x'])\n"
    (finding,) = scan_source("a.py", source, "python", OPTS)
    assert finding.rule_id == "python.taint.code-injection"
    assert {e.value for e in finding.engines} == {"rule", "taint"}


def test_bandit_corroborates():
    source = "import pickle\ndef load(b):\n    return pickle.loads(b)\n"
    (finding,) = scan_source("a.py", source, "python", ScanOptions(use_bandit=True))
    assert {e.value for e in finding.engines} == {"rule", "bandit"}


def test_fingerprint_survives_line_shift():
    base = "import pickle\npickle.loads(x)\n"
    (a,) = scan_source("a.py", base, "python", OPTS)
    (b,) = scan_source("a.py", "# comentário novo\n\n" + base, "python", OPTS)
    assert a.line != b.line
    assert a.fingerprint == b.fingerprint
