// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data added to a StringBuilder or a collection.
package com.example;

import java.util.ArrayList;
import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class BuildersController {
    private JdbcTemplate jdbc;

    @GetMapping("/builder")
    public Object builder(@RequestParam String name, @RequestParam String id) {
        StringBuilder query = new StringBuilder("SELECT * FROM users WHERE name = '");
        query.append(name).append("'");
        // ruleid: secreview.java.taint-sql
        jdbc.queryForList(query.toString());
        StringBuilder byId = new StringBuilder("SELECT * FROM users WHERE id = ");
        byId.append(Integer.parseInt(id));
        // ok: secreview.java.taint-sql
        return jdbc.queryForList(byId.toString());
    }

    @GetMapping("/columns")
    public Object columns(@RequestParam String column) {
        List<String> columns = new ArrayList<>();
        columns.add(column);
        // ruleid: secreview.java.taint-sql
        return jdbc.queryForList("SELECT " + String.join(", ", columns) + " FROM users");
    }
}
