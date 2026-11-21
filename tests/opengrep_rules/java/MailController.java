// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Password reset links built from the Host header, and mail headers built from request data.
package com.example;

import javax.mail.internet.MimeMessage;
import javax.servlet.http.HttpServletRequest;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
public class MailController {
    private String baseUrl;

    @PostMapping("/password-reset")
    public void reset(HttpServletRequest request, @RequestParam String email, String token) {
        SimpleMailMessage mail = new SimpleMailMessage();
        String link = ServletUriComponentsBuilder.fromCurrentContextPath().path("/reset").queryParam("token", token).toUriString();
        // ruleid: secreview.java.taint-host-header
        mail.setText("Open " + link);
        // ruleid: secreview.java.taint-host-header
        mail.setText("Open https://" + request.getServerName() + "/reset?token=" + token);
        // ok: secreview.java.taint-host-header
        mail.setText("Open " + baseUrl + "/reset?token=" + token);
    }

    @PostMapping("/contact")
    public void contact(@RequestParam String subject, MimeMessage message) throws Exception {
        // ruleid: secreview.java.taint-mail-header
        message.setSubject(subject);
        // ok: secreview.java.taint-mail-header
        message.setSubject(subject.replaceAll("[\r\n]", " "));
    }
}
