"""Regressão: o corpus rotulado não pode perder recall nem ganhar ruído."""

from benchmark.run_benchmark import run


def test_benchmark_quality_floor():
    _expected, results = run()
    main = results["Sentinela (regras + taint + Bandit)"]
    assert main.recall >= 0.95, main.missed
    assert main.precision >= 0.70, main.false_positives


def test_beats_bandit_on_python():
    _expected, results = run()
    assert results["Sentinela (só Python, para comparar)"].f1 > results["Bandit sozinho (só Python)"].f1
