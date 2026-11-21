// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data encoded in a URL whose host is fixed.
package com.example

import java.net.URLEncoder
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate

@RestController
class SanitizersController(private val rest: RestTemplate) {
    @GetMapping("/profile")
    fun profile(@RequestParam user: String): String? {
        // ok: secreview.kotlin.taint-ssrf
        return rest.getForObject("https://api.example.com/users?name=" + URLEncoder.encode(user, "UTF-8"), String::class.java)
    }
}
