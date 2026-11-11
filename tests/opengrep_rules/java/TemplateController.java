// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package com.example;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.io.StringWriter;
import javax.crypto.SecretKey;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.Velocity;
import org.springframework.web.bind.annotation.*;

@RestController
public class TemplateController {

    private SecretKey key;

    @PostMapping("/preview")
    public String preview(@RequestParam String template, @RequestParam String name) {
        VelocityContext context = new VelocityContext();
        context.put("name", name);
        StringWriter out = new StringWriter();
        // ruleid: secreview.java.taint-template-injection
        Velocity.evaluate(context, out, "preview", template);
        // ok: secreview.java.taint-template-injection
        Velocity.evaluate(context, out, "preview", "Hello $name");
        return out.toString();
    }

    Object claims(String token) {
        // ruleid: secreview.java.jwt-signature-not-verified
        Object unsigned = Jwts.parser().build().parse(token);
        // ruleid: secreview.java.jwt-signature-not-verified
        String subject = JWT.decode(token).getSubject();
        // ruleid: secreview.java.jwt-signature-not-verified
        Object plain = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJwt(token);
        // ok: secreview.java.jwt-signature-not-verified
        Object verified = Jwts.parser().verifyWith(key).build().parse(token);
        // ok: secreview.java.jwt-signature-not-verified
        Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
        // ok: secreview.java.jwt-signature-not-verified
        JWT.require(Algorithm.HMAC256("secret")).build().verify(token);
        return unsigned + subject + plain + verified + claims;
    }

    SSLContext tls(SSLSocket socket) throws Exception {
        // ruleid: secreview.java.tls-weak-version
        SSLContext legacy = SSLContext.getInstance("TLSv1.1");
        // ruleid: secreview.java.tls-weak-version
        socket.setEnabledProtocols(new String[] {"TLSv1", "TLSv1.2"});
        // ok: secreview.java.tls-weak-version
        SSLContext.getInstance("TLS");
        // ok: secreview.java.tls-weak-version
        return SSLContext.getInstance("TLSv1.3");
    }
}
