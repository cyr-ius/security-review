// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data naming a module, a class or a method reached by reflection.
import org.springframework.web.bind.annotation.*

@RestController
class ReflectionController {
    @PostMapping("/action")
    fun action(@RequestParam type: String): String {
        // ruleid: secreview.kotlin.taint-unsafe-reflection
        val handler = Class.forName("com.example.handlers.$type")
        // ok: secreview.kotlin.taint-unsafe-reflection
        val fixed = Class.forName("com.example.handlers.Export")
        return handler.name + fixed.name
    }
}
