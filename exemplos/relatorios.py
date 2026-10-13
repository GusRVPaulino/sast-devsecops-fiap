"""Endpoint de relatórios — PR de demonstração do Security Gate.

Este arquivo tem uma SQL Injection proposital para mostrar o Sentinela
comentando no PR e bloqueando o merge. Não faça merge deste PR.
"""

from flask import Flask, request

app = Flask(__name__)


@app.get("/relatorios")
def relatorio_por_cliente():
    cliente = request.args.get("cliente")
    consulta = f"SELECT * FROM vendas WHERE cliente = '{cliente}'"
    cursor = app.config["DB"].cursor()
    cursor.execute(consulta)
    return {"linhas": cursor.fetchall()}


@app.get("/relatorios/pagina")
def pagina():
    numero = int(request.args.get("n", "1"))
    cursor = app.config["DB"].cursor()
    cursor.execute(f"SELECT * FROM vendas LIMIT 50 OFFSET {numero * 50}")
    return {"linhas": cursor.fetchall()}
