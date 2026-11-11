// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Fully qualified class names, as written in the OWASP Benchmark, must match like imported ones.
package com.example;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Benchmark {

    public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String param = request.getParameter("name");
        // ruleid: secreview.java.taint-path-traversal
        java.io.File file = new java.io.File("/srv/files", param);
        // ok: secreview.java.taint-path-traversal
        java.io.File fixed = new java.io.File("/srv/files", "report.pdf");
        // ruleid: secreview.java.weak-hash
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        // ok: secreview.java.weak-hash
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        // ruleid: secreview.java.weak-cipher
        javax.crypto.Cipher des = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");
        // ok: secreview.java.weak-cipher
        javax.crypto.Cipher gcm = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.servlet.http.Cookie cookie = new javax.servlet.http.Cookie("session", param);
        // ruleid: secreview.java.cookie-insecure
        cookie.setSecure(false);
        // ok: secreview.java.cookie-insecure
        cookie.setSecure(true);
        response.addCookie(cookie);
    }

    public String xpath(HttpServletRequest request, org.w3c.dom.Document document) throws Exception {
        String name = request.getParameter("name");
        javax.xml.xpath.XPath xp = javax.xml.xpath.XPathFactory.newInstance().newXPath();
        // ruleid: secreview.java.taint-xpath-injection
        String found = xp.evaluate("/users/user[@name='" + name + "']/id", document);
        // ok: secreview.java.taint-xpath-injection
        String all = xp.evaluate("/users/user/id", document);
        return found + all;
    }

    public void session(HttpServletRequest request, HttpServletResponse response) throws Exception {
        java.util.Enumeration<String> names = request.getParameterNames();
        String first = names.nextElement();
        // ruleid: secreview.java.taint-trust-boundary
        request.getSession().putValue(first, "10340");
        javax.servlet.http.HttpSession session = request.getSession();
        // ruleid: secreview.java.taint-trust-boundary
        session.setAttribute("userid", request.getParameter("id"));
        // ok: secreview.java.taint-trust-boundary
        session.setAttribute("userid", "guest");
        String header = request.getHeader("X-Name");
        // ruleid: secreview.java.taint-xss-response
        response.getWriter().printf(java.util.Locale.US, "Hello %s", header);
        // ok: secreview.java.taint-xss-response
        response.getWriter().printf(java.util.Locale.US, "Hello %s", "world");
        String sql = "SELECT * FROM users WHERE name = '" + header + "'";
        // ruleid: secreview.java.taint-sql
        org.owasp.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, Long.class);
        // ok: secreview.java.taint-sql
        restTemplate.execute(header, org.springframework.http.HttpMethod.GET, null, null);
    }

    private org.springframework.web.client.RestTemplate restTemplate;
}
