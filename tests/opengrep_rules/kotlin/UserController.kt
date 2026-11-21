// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Spring controllers in Kotlin.
package com.example

import java.io.File
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.*
import org.springframework.web.client.RestTemplate

@RestController
class UserController(private val jdbc: JdbcTemplate, private val rest: RestTemplate) {
    @GetMapping("/users")
    fun search(@RequestParam name: String): Any {
        // ruleid: secreview.kotlin.taint-sql
        return jdbc.queryForList("SELECT * FROM users WHERE name = '$name'")
    }

    @GetMapping("/users/by-mail")
    fun implicit(mail: String, page: Int): Any =
        // ruleid: secreview.kotlin.taint-sql
        jdbc.queryForList("SELECT * FROM users WHERE mail = '" + mail + "' LIMIT 10 OFFSET " + page)

    @PostMapping("/users/filter")
    fun filter(@RequestBody form: UserForm): Any {
        val query = StringBuilder("SELECT * FROM users WHERE name = '")
        query.append(form.name).append("'")
        // ruleid: secreview.kotlin.taint-sql
        return jdbc.queryForList(query.toString())
    }

    @GetMapping("/users/{id}")
    fun byId(@PathVariable id: String): Any {
        // ok: secreview.kotlin.taint-sql
        jdbc.queryForList("SELECT * FROM users WHERE id = " + id.toInt())
        // ok: secreview.kotlin.taint-sql
        return jdbc.queryForList("SELECT * FROM users WHERE id = ?", id)
    }

    @GetMapping("/tools")
    fun tools(@RequestParam host: String, @RequestParam file: String, @RequestParam next: String): String {
        // ruleid: secreview.kotlin.taint-command
        Runtime.getRuntime().exec("ping -c 1 $host")
        // ok: secreview.kotlin.taint-command
        ProcessBuilder("ping", "-c", "1", host.toInt().toString()).start()
        // ruleid: secreview.kotlin.taint-path-traversal
        File("/data", file).readText()
        // ok: secreview.kotlin.taint-path-traversal
        File("/data", File(file).name).readText()
        // ruleid: secreview.kotlin.taint-ssrf
        rest.getForObject(host, String::class.java)
        // ok: secreview.kotlin.taint-ssrf
        rest.getForObject("https://api.example.com/hosts/{host}", String::class.java, host)
        // ruleid: secreview.kotlin.taint-regex-injection
        Regex(file)
        // ok: secreview.kotlin.taint-regex-injection
        Regex(Regex.escape(file))
        // ruleid: secreview.kotlin.taint-log-injection
        log.info("ping $host")
        // ok: secreview.kotlin.taint-log-injection
        log.info("ping {}", host.replace("\n", ""))
        // ruleid: secreview.kotlin.taint-open-redirect
        return "redirect:" + next
    }
}
