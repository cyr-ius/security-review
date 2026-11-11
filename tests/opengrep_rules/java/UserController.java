// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package com.example;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.ObjectInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.naming.InitialContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class UserController {

    private final JdbcTemplate jdbc;
    private final RestTemplate rest;
    private final Connection connection;

    UserController(JdbcTemplate jdbc, RestTemplate rest, Connection connection) {
        this.jdbc = jdbc;
        this.rest = rest;
        this.connection = connection;
    }

    @GetMapping("/users")
    public Object users(@RequestParam("name") String name, @RequestParam String id) throws Exception {
        Statement statement = connection.createStatement();
        // ruleid: secreview.java.taint-sql
        statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: secreview.java.taint-sql
        jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: secreview.java.taint-sql
        jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
        PreparedStatement prepared = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        prepared.setString(1, name);
        // ruleid: secreview.java.taint-sql
        statement.execute("DELETE FROM users WHERE name = '" + name + "'");
        // ok: secreview.java.taint-sql
        upload.execute(file, name);
        // ok: secreview.java.taint-sql
        return statement.executeQuery("SELECT * FROM users WHERE id = " + Long.parseLong(id));
    }

    @PostMapping("/ping")
    public void ping(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        // ruleid: secreview.java.taint-command
        Runtime.getRuntime().exec("ping -c 1 " + host);
        // ruleid: secreview.java.taint-command
        new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        // ok: secreview.java.taint-command
        Runtime.getRuntime().exec(new String[] {"uptime"});
    }

    @GetMapping("/files/{name}")
    public byte[] file(@PathVariable String name) throws Exception {
        // ruleid: secreview.java.taint-path-traversal
        File target = new File("/srv/files/" + name);
        // ok: secreview.java.taint-path-traversal
        Path safe = Paths.get("/srv/files").resolve(Paths.get(name).getFileName());
        return java.nio.file.Files.readAllBytes(target.toPath());
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        // ruleid: secreview.java.taint-ssrf
        rest.getForObject(url, String.class);
        // ruleid: secreview.java.taint-ssrf
        InputStream stream = new URL(url).openStream();
        // ruleid: secreview.java.taint-ssrf
        rest.getForObject(URI.create(url), String.class);
        // ok: secreview.java.taint-ssrf
        URI parsed = new URI(url);
        // ok: secreview.java.taint-ssrf
        return rest.getForObject("https://api.example.com/status", String.class);
    }

    @GetMapping("/login")
    public String login(@RequestParam("next") String next, HttpServletResponse response) throws Exception {
        // ruleid: secreview.java.taint-open-redirect
        response.sendRedirect(next);
        // ok: secreview.java.taint-open-redirect
        response.sendRedirect("/home");
        // ruleid: secreview.java.taint-open-redirect
        return "redirect:" + next;
    }

    @GetMapping("/hello")
    public void hello(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getParameter("name");
        // ruleid: secreview.java.taint-xss-response
        response.getWriter().write("<p>Hello " + name + "</p>");
        // ok: secreview.java.taint-xss-response
        response.getWriter().write("<p>Hello " + org.springframework.web.util.HtmlUtils.htmlEscape(name) + "</p>");
    }

    @PostMapping("/eval")
    public Object eval(@RequestBody String expression) {
        // ruleid: secreview.java.taint-expression-injection
        return new SpelExpressionParser().parseExpression(expression).getValue();
    }

    @GetMapping("/resource")
    public Object resource(@RequestParam String name) throws Exception {
        // ruleid: secreview.java.taint-jndi-ldap-injection
        return new InitialContext().lookup(name);
    }

    @GetMapping("/datasource")
    public Object datasource() throws Exception {
        // ok: secreview.java.taint-jndi-ldap-injection
        return new InitialContext().lookup("java:comp/env/jdbc/app");
    }

    Object readUnsafe(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        // ruleid: secreview.java.object-deserialization
        return stream.readObject();
    }

    Object readFiltered(InputStream input) throws Exception {
        ObjectInputStream stream = new ObjectInputStream(input);
        stream.setObjectInputFilter(java.io.ObjectInputFilter.Config.createFilter("com.example.*;!*"));
        // ok: secreview.java.object-deserialization
        return stream.readObject();
    }

    Object parseUnsafe(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: secreview.java.xxe-xml-parser
        return factory.newDocumentBuilder().parse(input);
    }

    Object parseSafe(InputStream input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: secreview.java.xxe-xml-parser
        return factory.newDocumentBuilder().parse(input);
    }

    Object streamUnsafe(InputStream input) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        // ruleid: secreview.java.xxe-stax-parser
        return factory.createXMLStreamReader(input);
    }

    Object streamSafe(InputStream input) throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        // ok: secreview.java.xxe-stax-parser
        return factory.createXMLStreamReader(input);
    }

    void security(HttpSecurity http) throws Exception {
        // ruleid: secreview.java.spring-csrf-disabled
        http.csrf(csrf -> csrf.disable());
        // ok: secreview.java.spring-csrf-disabled
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/webhook"));
    }

    static class TrustAll implements X509TrustManager {
        public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        // ruleid: secreview.java.trust-all-certificates
        public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        // ruleid: secreview.java.trust-all-certificates
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }

    void hosts(javax.net.ssl.HttpsURLConnection connection) {
        // ruleid: secreview.java.hostname-verification-disabled
        connection.setHostnameVerifier((host, session) -> true);
        // ok: secreview.java.hostname-verification-disabled
        connection.setHostnameVerifier((host, session) -> host.equals("api.example.com"));
    }

    void crypto() throws Exception {
        // ruleid: secreview.java.weak-cipher
        Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ruleid: secreview.java.weak-cipher
        Cipher.getInstance("AES");
        // ok: secreview.java.weak-cipher
        Cipher.getInstance("AES/GCM/NoPadding");
        // ruleid: secreview.java.weak-hash
        MessageDigest.getInstance("MD5");
        // ok: secreview.java.weak-hash
        MessageDigest.getInstance("SHA-256");
    }

    void cookies(HttpServletResponse response) {
        Cookie cookie = new Cookie("session", "value");
        // ruleid: secreview.java.cookie-insecure
        cookie.setHttpOnly(false);
        // ok: secreview.java.cookie-insecure
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    void jackson(ObjectMapper mapper) {
        // ruleid: secreview.java.jackson-default-typing
        mapper.enableDefaultTyping();
    }

    // ruleid: secreview.java.jackson-default-typing
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    static class Payload { }

    // ok: secreview.java.jackson-default-typing
    @JsonTypeInfo(use = JsonTypeInfo.Id.NAME)
    static class Named { }
}
