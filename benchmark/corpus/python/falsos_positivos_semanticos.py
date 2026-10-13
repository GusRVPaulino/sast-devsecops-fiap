"""Corpus rotulado (Python): código SEGURO que regras e taint sinalizam.

Decidir que é seguro exige ler o contexto (allowlist, regex, origem confiável,
código de teste). É exatamente o trabalho da triagem por IA. Todo achado aqui
conta como falso positivo.
"""

import os
import pickle
import re
import subprocess

from flask import request

COLUNAS_ORDENACAO = {"nome", "preco", "criado_em"}
HOSTNAME = re.compile(r"[a-z0-9.-]{1,253}")


def listar(cursor):
    coluna = request.args.get("ordem", "nome")
    if coluna not in COLUNAS_ORDENACAO:
        raise ValueError("coluna inválida")
    cursor.execute(f"SELECT id, nome FROM produtos ORDER BY {coluna}")


def ping():
    host = request.args["host"]
    if not HOSTNAME.fullmatch(host):
        raise ValueError("host inválido")
    os.system("ping -c 1 " + host)


def carregar_modelo():
    # Arquivo gerado pelo nosso pipeline de treino no build; nunca vem do usuário.
    with open("/opt/app/modelo.pkl", "rb") as arquivo:
        return pickle.loads(arquivo.read())


def migrar():
    pasta = os.path.dirname(__file__) + "/migrations"
    subprocess.run("alembic -c " + pasta + "/alembic.ini upgrade head", shell=True, check=True)


def test_login_rejeita_senha_errada(client):
    password = "Errada#2026!"
    resposta = client.post("/login", data={"usuario": "ana", "password": password})
    assert resposta.status_code == 401
