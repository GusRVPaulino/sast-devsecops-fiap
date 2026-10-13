"""Corpus rotulado (Python): código seguro parecido com o vulnerável. Nenhum achado é esperado."""

import ast
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path

import requests
import yaml
from flask import request

SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]
PASSWORD_FIELD = "password"
TOKEN_HEADER = "X-Auth-Token"
senha_exemplo = "changeme"
token_ajuda = "Cole aqui o token que você recebeu por e-mail"


def buscar_produto(cursor):
    produto_id = request.args["id"]
    cursor.execute("SELECT * FROM produtos WHERE id = %s", (produto_id,))


def contar(cursor):
    cursor.execute("SELECT COUNT(*) FROM produtos")


def diagnostico():
    host = shlex.quote(request.args["host"])
    subprocess.run(["ping", "-c", "1", host], check=True)


def converter():
    nome = os.path.basename(request.args["arquivo"])
    subprocess.run(["convert", nome, "miniatura.png"], check=True)


def listar_tmp():
    subprocess.run("ls -la /tmp", shell=True, check=True)


def calculadora():
    return ast.literal_eval(request.args["expressao"])


def constante():
    return eval("40 + 2")


def restaurar_sessao():
    return json.loads(request.get_data())


def carregar_config(texto):
    return yaml.safe_load(texto)


def baixar_nota():
    nome = os.path.basename(request.args["nota"])
    return (Path("/srv/notas") / nome).read_text()


def pagina():
    numero = int(request.args["pagina"])
    with open(f"/srv/paginas/{numero}.html") as arquivo:
        return arquivo.read()


def status():
    return requests.get("https://status.example.com/health", timeout=5)


def checksum(dados):
    return hashlib.sha256(dados).hexdigest()
