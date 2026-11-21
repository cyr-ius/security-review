// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Spring binds handler parameters without annotation too.
package com.example;

import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public class SourcesController {
    private JdbcTemplate jdbc;

    @GetMapping("/search")
    public Object search(String name, int page) {
        // ruleid: secreview.java.taint-sql
        jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
        // ok: secreview.java.taint-sql
        return jdbc.queryForList("SELECT * FROM users LIMIT 10 OFFSET " + page);
    }

    @PostMapping("/register")
    public Object register(UserForm form) {
        // ruleid: secreview.java.taint-sql
        return jdbc.queryForList("SELECT * FROM users WHERE mail = '" + form.getMail() + "'");
    }

    @GetMapping("/me")
    public Object me(@AuthenticationPrincipal String login, HttpServletRequest request) {
        // ok: secreview.java.taint-sql
        return jdbc.queryForList("SELECT * FROM users WHERE login = '" + login + "'");
    }
}
