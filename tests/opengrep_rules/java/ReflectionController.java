// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data naming a module, a class or a method reached by reflection.
import org.springframework.web.bind.annotation.*;

@RestController
class ReflectionController {
    @PostMapping("/action")
    String action(@RequestParam String type, @RequestParam String method) throws Exception {
        // ruleid: secreview.java.taint-unsafe-reflection
        Class<?> handler = Class.forName("com.example.handlers." + type);
        // ruleid: secreview.java.taint-unsafe-reflection
        Object result = handler.getMethod(method).invoke(null);
        // ok: secreview.java.taint-unsafe-reflection
        Class<?> fixed = Class.forName("com.example.handlers.Export");
        return String.valueOf(result);
    }
}
