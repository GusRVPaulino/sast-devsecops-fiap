"""Corpus rotulado (Python): vulnerabilidades reais. `# expect: CWE-N` marca a verdade."""

import hashlib
import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, render_template_string, request

app = Flask(__name__)
SMTP_PASSWORD = "Mx7#pQ2!vLr9"  # expect: CWE-798
AWS_ACCESS_KEY_ID = "AKIAZ4Q7EXAMPLE2MPLX"  # expect: CWE-798


def buscar_produto(cursor):
    produto_id = request.args["id"]
    cursor.execute(f"SELECT * FROM produtos WHERE id = {produto_id}")  # expect: CWE-89
    return cursor.fetchone()


def pesquisar(cursor):
    termo = request.form.get("q")
    sql = "SELECT * FROM produtos WHERE nome LIKE '%" + termo + "%'"
    cursor.execute(sql)  # expect: CWE-89


def diagnostico():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)  # expect: CWE-78


def converter():
    arquivo = request.args["arquivo"]
    subprocess.run(f"convert {arquivo} miniatura.png", shell=True)  # expect: CWE-78


def gerar_relatorio(caminho):
    subprocess.call("relatorio --entrada " + caminho, shell=True)  # expect: CWE-78


def calculadora():
    return eval(request.args["expressao"])  # expect: CWE-95


def restaurar_sessao():
    return pickle.loads(request.get_data())  # expect: CWE-502


def carregar_config(texto):
    return yaml.load(texto, Loader=yaml.Loader)  # expect: CWE-502


def baixar_nota():
    nome = request.args["nota"]
    with open("/srv/notas/" + nome) as arquivo:  # expect: CWE-22
        return arquivo.read()


def pre_visualizar():
    return requests.get(request.json["url"], timeout=5)  # expect: CWE-918


def saudacao():
    nome = request.args.get("nome", "")
    return render_template_string("<h1>Olá " + nome + "</h1>")  # expect: CWE-79


def hash_senha(senha):
    return hashlib.md5(senha.encode()).hexdigest()  # expect: CWE-327


def integrar_parceiro():
    return requests.post("https://parceiro.example.com/api", verify=False, timeout=5)  # expect: CWE-295


def registrar(cursor, usuario):
    _salvar(cursor, request.form["email"])


def _salvar(cursor, email):
    cursor.execute("INSERT INTO usuarios (email) VALUES ('" + email + "')")  # expect: CWE-89


if __name__ == "__main__":
    app.run(debug=True)  # expect: CWE-489
