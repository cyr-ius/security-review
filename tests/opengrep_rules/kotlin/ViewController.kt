// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data choosing the view or the template rendered.
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.*

@Controller
class ViewController {
    @GetMapping("/doc")
    fun doc(@RequestParam section: String): String {
        // ruleid: secreview.kotlin.taint-view-injection
        return "docs/$section"
    }

    @GetMapping("/help")
    fun help(@RequestParam topic: String): String {
        // ok: secreview.kotlin.taint-view-injection
        return "help"
    }
}
