// Corpus rotulado (Java): vulnerabilidades reais. `// expect: CWE-N` marca a verdade.
package br.fiap.loja;

import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;

public class PedidoController {
    private static final String DB_PASSWORD = "Pg#Prod2026!xq";  // expect: CWE-798
    private Connection conn;

    @GetMapping("/pedidos")
    public String buscar(@RequestParam String cliente) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM pedidos WHERE cliente = '" + cliente + "'";
        ResultSet rs = stmt.executeQuery(sql);  // expect: CWE-89
        return "ok";
    }

    public void exportar(HttpServletRequest request) throws Exception {
        String formato = request.getParameter("formato");
        Runtime.getRuntime().exec("exportar --formato " + formato);  // expect: CWE-78
    }

    public byte[] anexo(HttpServletRequest request) throws Exception {
        File arquivo = new File("/srv/anexos/" + request.getParameter("nome"));  // expect: CWE-22
        return java.nio.file.Files.readAllBytes(arquivo.toPath());
    }

    public Object restaurar(HttpServletRequest request) throws Exception {
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();  // expect: CWE-502
    }

    public byte[] resumo(byte[] dados) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");  // expect: CWE-327
        return md.digest(dados);
    }

    public Cipher cifra() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");  // expect: CWE-327
    }

    @GetMapping("/saudacao")
    public void saudacao(@RequestParam String nome, HttpServletResponse response) throws Exception {
        PrintWriter out = response.getWriter();
        out.println("<h1>Olá " + nome + "</h1>");  // expect: CWE-79
    }
}
