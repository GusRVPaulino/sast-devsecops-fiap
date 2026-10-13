// Corpus rotulado (JavaScript): código SEGURO que regras e taint sinalizam.
// Todo achado aqui conta como falso positivo.
const { exec } = require("child_process");

const RELATORIOS = new Set(["vendas", "estoque", "clientes"]);
const DESTINOS = new Set(["/", "/painel", "/conta"]);

app.post("/relatorio", (req, res) => {
  const tipo = req.body.tipo;
  if (!RELATORIOS.has(tipo)) return res.status(400).end();
  exec("gerar-relatorio " + tipo, () => res.end());
});

app.get("/sair", (req, res) => {
  const destino = req.query.next;
  res.redirect(DESTINOS.has(destino) ? destino : "/");
});

app.get("/eco", (req, res) => {
  const id = req.query.id;
  if (!/^[0-9]{1,9}$/.test(id)) return res.status(400).end();
  res.send("Pedido " + id);
});
