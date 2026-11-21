// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Mass assignment: the whole request, or an entity bound from it, saved as it is.
import org.springframework.web.bind.annotation.*;

@RestController
class AccountController {
    private final UserRepository users;

    @PostMapping("/users")
    User create(@RequestBody User user) {
        // ruleid: secreview.java.mass-assignment-bound-entity
        return users.save(user);
    }

    @PutMapping("/users/{id}")
    User update(@PathVariable long id, @Valid @RequestBody User user) {
        // ruleid: secreview.java.mass-assignment-bound-entity
        return users.save(user);
    }

    @PostMapping("/accounts")
    User register(@RequestBody NewUser form) {
        User user = new User(form.name(), form.email());
        // ok: secreview.java.mass-assignment-bound-entity
        return users.save(user);
    }
}
