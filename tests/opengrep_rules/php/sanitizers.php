<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data encoded in a URL whose host is fixed.

function profile() {
    // ok: secreview.php.taint-ssrf
    $ch = curl_init('https://api.example.com/users/' . rawurlencode($_GET['user']));
    return curl_exec($ch);
}
