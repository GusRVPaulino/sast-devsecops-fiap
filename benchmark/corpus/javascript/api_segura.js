// Corpus rotulado (JavaScript): código seguro parecido com o vulnerável. Nenhum achado é esperado.
const express = require("express");
const { execFile } = require("child_process");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;
const PASSWORD_FIELD = "senha";

app.get("/pedidos/:id", async (req, res) => {
  const rows = await db.query("SELECT * FROM pedidos WHERE id = $1", [req.params.id]);
  res.json(rows);
});

app.post("/ping", (req, res) => {
  execFile("ping", ["-c", "1", req.body.host], () => res.end());
});

app.get("/pagina", async (req, res) => {
  const pagina = parseInt(req.query.p, 10);
  const rows = await db.query(`SELECT * FROM produtos LIMIT 20 OFFSET ${pagina * 20}`);
  res.json(rows);
});

app.get("/arquivo", (req, res) => {
  const nome = path.basename(req.query.nome);
  res.sendFile(path.join("/srv/uploads", nome));
});

app.get("/busca", (req, res) => {
  res.json({ termo: req.query.q });
});

function mostrarNome(nome) {
  document.getElementById("titulo").textContent = nome;
  document.getElementById("rodape").innerHTML = "<b>Loja</b>";
}

function checksum(dados) {
  return crypto.createHash("sha256").update(dados).digest("hex");
}

function agendar(acao) {
  setTimeout(() => acao(), 1000);
}
