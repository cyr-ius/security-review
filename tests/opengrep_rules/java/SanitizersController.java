// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data encoded in a URL whose host is fixed.
package com.example;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class SanitizersController {
    private RestTemplate rest;

    @GetMapping("/profile")
    public String profile(@RequestParam String user) {
        // ok: secreview.java.taint-ssrf
        return rest.getForObject("https://api.example.com/users?name=" + URLEncoder.encode(user, StandardCharsets.UTF_8), String.class);
    }
}
