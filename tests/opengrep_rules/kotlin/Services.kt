// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Kotlin taint rules ported from Java, Android intent redirection and zip slip.
import org.springframework.web.bind.annotation.*

@RestController
class ServicesController(private val mongo: MongoTemplate, private val mailSender: JavaMailSender) {
    @PostMapping("/calc")
    fun calc(@RequestParam expression: String): Any? {
        val engine = ScriptEngineManager().getEngineByName("js")
        // ruleid: secreview.kotlin.taint-code-eval
        engine.eval(expression)
        // ok: secreview.kotlin.taint-code-eval
        engine.eval("1 + 1")
        val parser = SpelExpressionParser()
        // ruleid: secreview.kotlin.taint-expression-injection
        parser.parseExpression(expression).getValue()
        // ok: secreview.kotlin.taint-expression-injection
        return parser.parseExpression("1 + 1").getValue()
    }

    @GetMapping("/directory")
    fun directory(@RequestParam user: String, @RequestParam resource: String): Any {
        val context = InitialDirContext()
        // ruleid: secreview.kotlin.taint-jndi-ldap-injection
        context.search("ou=people", "(uid=$user)", SearchControls())
        // ok: secreview.kotlin.taint-jndi-ldap-injection
        context.search("ou=people", "(uid=" + LdapEncoder.filterEncode(user) + ")", SearchControls())
        // ruleid: secreview.kotlin.taint-jndi-ldap-injection
        return InitialContext().lookup(resource)
    }

    @GetMapping("/notes")
    fun notes(@RequestParam filter: String, @RequestParam path: String): Any {
        // ruleid: secreview.kotlin.taint-nosql-injection
        mongo.find(BasicQuery(filter), Note::class.java)
        // ok: secreview.kotlin.taint-nosql-injection
        mongo.find(Query(Criteria.where("owner").`is`(filter)), Note::class.java)
        val xpath = XPathFactory.newInstance().newXPath()
        // ruleid: secreview.kotlin.taint-xpath-injection
        xpath.evaluate("//note[@path='$path']", document)
        // ok: secreview.kotlin.taint-xpath-injection
        return xpath.evaluate("//note[@id='1']", document)
    }

    @PostMapping("/preview")
    fun preview(@RequestParam body: String): String {
        val writer = StringWriter()
        // ruleid: secreview.kotlin.taint-template-injection
        Velocity.evaluate(VelocityContext(), writer, "preview", body)
        // ok: secreview.kotlin.taint-template-injection
        Velocity.evaluate(VelocityContext(), writer, "preview", "Hello")
        return writer.toString()
    }

    @PostMapping("/contact")
    fun contact(@RequestParam subject: String) {
        val message = MimeMessage(session)
        // ruleid: secreview.kotlin.taint-mail-header
        message.setSubject(subject)
        // ok: secreview.kotlin.taint-mail-header
        message.setSubject(subject.replace("\n", ""))
        // ok: secreview.kotlin.taint-mail-header
        message.setSubject("Contact")
    }

    @PostMapping("/login")
    fun login(request: HttpServletRequest, @RequestParam role: String) {
        // ruleid: secreview.kotlin.taint-trust-boundary
        request.getSession(true).setAttribute("role", role)
        // ok: secreview.kotlin.taint-trust-boundary
        request.getSession(true).setAttribute("role", "user")
    }

    @PostMapping("/reset")
    fun reset(request: HttpServletRequest, @RequestParam email: String) {
        val link = "https://" + request.getHeader("Host") + "/reset?token=" + token
        val message = SimpleMailMessage()
        // ruleid: secreview.kotlin.taint-host-header
        message.setText("Reset your password: $link")
        // ok: secreview.kotlin.taint-host-header
        message.setText("Reset your password: https://example.com/reset?token=$token")
    }
}

class ForwardActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val next = intent.getParcelableExtra<Intent>("next")
        // ruleid: secreview.kotlin.taint-intent-redirection
        startActivity(next)
        // ok: secreview.kotlin.taint-intent-redirection
        startActivity(Intent(this, HomeActivity::class.java))
    }
}

fun unzip(zip: ZipInputStream, target: File) {
    var entry = zip.nextEntry
    while (entry != null) {
        // ruleid: secreview.kotlin.zip-slip
        File(target, entry.name).outputStream().use { zip.copyTo(it) }
        entry = zip.nextEntry
    }
}

fun unzipSafely(zip: ZipInputStream, target: File) {
    var entry = zip.nextEntry
    while (entry != null) {
        // ok: secreview.kotlin.zip-slip
        val file = File(target, entry.name)
        if (!file.canonicalPath.startsWith(target.canonicalPath + File.separator)) throw SecurityException("zip slip")
        file.outputStream().use { zip.copyTo(it) }
        entry = zip.nextEntry
    }
}
