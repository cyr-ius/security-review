// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
package com.example;

import com.thoughtworks.xstream.XStream;
import groovy.lang.GroovyShell;
import java.beans.XMLDecoder;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@RestController
public class ScriptController {

    @PostMapping("/calc")
    public Object calc(@RequestParam String expression) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        // ruleid: secreview.java.taint-code-eval
        Object result = engine.eval(expression);
        // ruleid: secreview.java.taint-code-eval
        new GroovyShell().evaluate(expression);
        // ok: secreview.java.taint-code-eval
        engine.eval("1 + 1");
        return result;
    }

    Object decode(InputStream input) {
        // ruleid: secreview.java.xml-decoder
        XMLDecoder decoder = new XMLDecoder(input);
        return decoder.readObject();
    }

    Object xstream(String xml) {
        XStream xstream = new XStream();
        // ruleid: secreview.java.xstream-without-allowlist
        return xstream.fromXML(xml);
    }

    Object xstreamAllowed(String xml) {
        XStream xstream = new XStream();
        xstream.allowTypes(new Class[] {Order.class});
        // ok: secreview.java.xstream-without-allowlist
        return xstream.fromXML(xml);
    }

    // ruleid: secreview.java.cors-any-origin-credentials
    @CrossOrigin(originPatterns = "*", allowCredentials = "true")
    @GetMapping("/profile")
    public String profile() {
        return "profile";
    }

    // ok: secreview.java.cors-any-origin-credentials
    @CrossOrigin(origins = "https://app.example.com", allowCredentials = "true")
    @GetMapping("/settings")
    public String settings() {
        return "settings";
    }

    WebMvcConfigurer cors() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                // ruleid: secreview.java.cors-any-origin-credentials
                registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
                // ok: secreview.java.cors-any-origin-credentials
                registry.addMapping("/public/**").allowedOriginPatterns("*");
            }
        };
    }

    boolean verify(String signature, String expectedSignature, byte[] mac, byte[] expectedMac) {
        // ruleid: secreview.java.non-constant-time-compare
        boolean same = signature.equals(expectedSignature);
        // ruleid: secreview.java.non-constant-time-compare
        boolean bytes = Arrays.equals(mac, expectedMac);
        // ok: secreview.java.non-constant-time-compare
        boolean safe = MessageDigest.isEqual(mac, expectedMac);
        // ok: secreview.java.non-constant-time-compare
        boolean empty = signature.equals("");
        return same && bytes && safe && empty;
    }
}
