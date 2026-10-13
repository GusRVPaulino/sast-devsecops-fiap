// Corpus rotulado (Java): código seguro parecido com o vulnerável. Nenhum achado é esperado.
package br.fiap.loja;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.*;
import javax.crypto.Cipher;

public class PedidoSeguro {
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");
    private static final String PASSWORD_PARAM = "senha";
    private Connection conn;

    @GetMapping("/pedidos")
    public String buscar(@RequestParam String cliente) throws Exception {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM pedidos WHERE cliente = ?");
        ps.setString(1, cliente);
        ResultSet rs = ps.executeQuery();
        return "ok";
    }

    @GetMapping("/pagina")
    public String pagina(@RequestParam String p) throws Exception {
        int numero = Integer.parseInt(p);
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM pedidos LIMIT 20 OFFSET " + (numero * 20));
        return "ok";
    }

    public void backup() throws Exception {
        new ProcessBuilder("pg_dump", "loja").start();
    }

    public byte[] resumo(byte[] dados) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(dados);
    }

    public Cipher cifra() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public byte[] token() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
