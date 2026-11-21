// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
import org.springframework.web.bind.annotation.*

@RestController
class MirrorController {
    @PostMapping("/mirror")
    fun mirror(@RequestParam url: String): String {
        // ruleid: secreview.kotlin.taint-argument-injection
        ProcessBuilder("git", "clone", url, "/srv/mirror").start()
        // ruleid: secreview.kotlin.taint-argument-injection
        ProcessBuilder(listOf("curl", "-s", url)).start()
        // ok: secreview.kotlin.taint-argument-injection
        ProcessBuilder("git", "clone", "--", url, "/srv/mirror").start()
        // ok: secreview.kotlin.taint-argument-injection
        ProcessBuilder("git", "clone", "--branch=$url", "https://example.com/repo").start()
        // ok: secreview.kotlin.taint-argument-injection
        ProcessBuilder("/opt/tools/report", url).start()
        return "ok"
    }
}
