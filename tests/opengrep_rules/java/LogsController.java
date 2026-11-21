// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Log injection, response splitting and regular expressions built from request data.
package com.example;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

@RestController
public class LogsController {
    private static final Logger log = LoggerFactory.getLogger(LogsController.class);

    @GetMapping("/login")
    public String login(@RequestParam String user) {
        // ruleid: secreview.java.taint-log-injection
        log.warn("failed login for " + user);
        // ruleid: secreview.java.taint-log-injection
        log.info("failed login for {}", user);
        // ok: secreview.java.taint-log-injection
        log.warn("failed login for {}", user.replaceAll("[\r\n]", "_"));
        return "ok";
    }

    @GetMapping("/download")
    public void download(@RequestParam String name, HttpServletResponse response) {
        // ruleid: secreview.java.taint-header-injection
        response.setHeader("Content-Disposition", "attachment; filename=" + name);
        // ok: secreview.java.taint-header-injection
        response.setHeader("Content-Disposition", "attachment; filename=" + URLEncoder.encode(name, StandardCharsets.UTF_8));
        // ok: secreview.java.taint-header-injection
        response.setHeader("X-Name", name.replace("\r", "").replace("\n", ""));
    }

    @GetMapping("/search")
    public boolean search(@RequestParam String term, @RequestParam String text) {
        // ruleid: secreview.java.taint-regex-injection
        boolean found = Pattern.compile(term).matcher(text).find();
        // ruleid: secreview.java.taint-regex-injection
        boolean whole = text.matches(term);
        // ok: secreview.java.taint-regex-injection
        boolean quoted = Pattern.compile(Pattern.quote(term)).matcher(text).find();
        // ok: secreview.java.taint-regex-injection
        boolean fixed = term.matches("^[a-z]+$");
        return found || whole || quoted || fixed;
    }
}
