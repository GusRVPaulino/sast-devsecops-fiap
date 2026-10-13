// Corpus rotulado (JavaScript): vulnerabilidades reais. `// expect: CWE-N` marca a verdade.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const axios = require("axios");

const app = express();
const JWT_SECRET = "s3gr3d0-Do-Jwt-2026";  // expect: CWE-798

function buscarPorId(db, id) {
  return db.query("SELECT * FROM pedidos WHERE id = " + id);  // expect: CWE-89
}

app.get("/pedidos/:id", (req, res) => {
  buscarPorId(db, req.params.id);
});

app.get("/busca", async (req, res) => {
  const termo = req.query.q;
  const rows = await db.query(`SELECT * FROM produtos WHERE nome LIKE '%${termo}%'`);  // expect: CWE-89
  res.send("<h2>Resultados para " + termo + "</h2>");  // expect: CWE-79
});

app.post("/ping", (req, res) => {
  exec("ping -c 1 " + req.body.host);  // expect: CWE-78
});

app.post("/calc", (req, res) => {
  res.json({ resultado: eval(req.body.expressao) });  // expect: CWE-95
});

app.get("/arquivo", (req, res) => {
  fs.readFile("/srv/uploads/" + req.query.nome, (err, data) => res.send(data));  // expect: CWE-22
});

app.get("/preview", async (req, res) => {
  const resposta = await axios.get(req.query.url);  // expect: CWE-918
  res.json(resposta.data);
});

app.get("/sair", (req, res) => {
  res.redirect(req.query.next);  // expect: CWE-601
});

function mostrarBoasVindas() {
  const nome = new URLSearchParams(location.search).get("nome");
  document.getElementById("titulo").innerHTML = "Olá, " + location.hash;  // expect: CWE-79
}

function checksum(dados) {
  return crypto.createHash("md5").update(dados).digest("hex");  // expect: CWE-327
}

function agendar(acao) {
  setTimeout("executar('" + acao + "')", 1000);  // expect: CWE-95
}
