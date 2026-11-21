// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Mass assignment: the whole request, or an entity bound from it, saved as it is.
import org.springframework.web.bind.annotation.*

@RestController
class AccountController(private val users: UserRepository) {
    @PostMapping("/users")
    fun create(@RequestBody user: User): User {
        // ruleid: secreview.kotlin.mass-assignment-bound-entity
        return users.save(user)
    }

    @PostMapping("/accounts")
    fun register(@RequestBody form: NewUser): User {
        // ok: secreview.kotlin.mass-assignment-bound-entity
        return users.save(User(name = form.name, email = form.email))
    }
}
