// Corpus rotulado (Java): código SEGURO que regras e taint sinalizam.
// Todo achado aqui conta como falso positivo.
package br.fiap.loja;

import java.sql.*;
import java.util.Set;

public class FalsosPositivosSemanticos {
    private static final Set<String> COLUNAS = Set.of("nome", "preco", "data");
    private Connection conn;

    @GetMapping("/produtos")
    public String listar(@RequestParam String ordem) throws Exception {
        if (!COLUNAS.contains(ordem)) {
            throw new IllegalArgumentException("coluna inválida");
        }
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM produtos ORDER BY " + ordem);
        return "ok";
    }

    @GetMapping("/backup")
    public void backup(@RequestParam String banco) throws Exception {
        if (!banco.matches("^(loja|estoque)$")) {
            throw new IllegalArgumentException("banco inválido");
        }
        Runtime.getRuntime().exec("pg_dump " + banco);
    }
}
