// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
class MirrorController {
    @PostMapping("/mirror")
    String mirror(@RequestParam String url) throws Exception {
        // ruleid: secreview.java.taint-argument-injection
        new ProcessBuilder("git", "clone", url, "/srv/mirror").start();
        // ruleid: secreview.java.taint-argument-injection
        new ProcessBuilder(List.of("curl", "-s", url)).start();
        // ruleid: secreview.java.taint-argument-injection
        Runtime.getRuntime().exec(new String[] {"git", "ls-remote", url});
        // ok: secreview.java.taint-argument-injection
        new ProcessBuilder("git", "clone", "--", url, "/srv/mirror").start();
        // ok: secreview.java.taint-argument-injection
        new ProcessBuilder("git", "clone", "--branch=" + url, "https://example.com/repo").start();
        // ok: secreview.java.taint-argument-injection
        new ProcessBuilder("/opt/tools/report", url).start();
        return "ok";
    }
}
