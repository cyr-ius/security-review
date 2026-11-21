<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Password reset links built from the Host header, and mail() headers built from request data.

function passwordReset($user, $token) {
    $link = 'https://' . $_SERVER['HTTP_HOST'] . '/reset?token=' . $token;
    // ruleid: secreview.php.taint-host-header
    mail($user->email, 'Reset your password', "Open $link");
    // ok: secreview.php.taint-host-header
    mail($user->email, 'Reset your password', 'Open ' . getenv('APP_URL') . '/reset?token=' . $token);
}

function contact() {
    $from = $_POST['email'];
    // ruleid: secreview.php.taint-mail-header
    mail('contact@example.com', 'Contact', $_POST['message'], "From: $from");
    // ruleid: secreview.php.taint-mail-header
    mail('contact@example.com', $_POST['subject'], 'Hello');
    $checked = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    // ok: secreview.php.taint-mail-header
    mail('contact@example.com', 'Contact', $_POST['message'], "From: $checked");
}
