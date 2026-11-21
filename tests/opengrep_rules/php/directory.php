<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// XPath, LDAP, NoSQL, regular expressions, logs, uploads and Dynamic LINQ.
function directory(Request $request, MongoDB\Collection $users)
{
    $name = $_GET['name'];
    $xpath = new DOMXPath($document);
    // ruleid: secreview.php.taint-xpath-injection
    $nodes = $xpath->query("//user[@name='" . $name . "']");
    // ok: secreview.php.taint-xpath-injection
    $nodes = $xpath->query("//user[@id='" . intval($name) . "']");
    // ruleid: secreview.php.taint-ldap-injection
    ldap_search($link, 'ou=people,dc=example,dc=com', "(uid=$name)");
    // ok: secreview.php.taint-ldap-injection
    ldap_search($link, 'ou=people,dc=example,dc=com', '(uid=' . ldap_escape($name, '', LDAP_ESCAPE_FILTER) . ')');
    // ruleid: secreview.php.taint-nosql-injection
    $user = $users->findOne(['username' => $_POST['username'], 'password' => $hash]);
    // ok: secreview.php.taint-nosql-injection
    $user = $users->findOne(['username' => (string) $_POST['username']]);
    // ruleid: secreview.php.taint-regex-injection
    preg_match('/' . $name . '/', $text);
    // ok: secreview.php.taint-regex-injection
    preg_match('/' . preg_quote($name, '/') . '/', $text);
    // ruleid: secreview.php.taint-log-injection
    error_log("search for " . $name);
    // ruleid: secreview.php.taint-log-injection
    Log::info("search for " . $name);
    // ok: secreview.php.taint-log-injection
    Log::info("search for " . str_replace(["\r", "\n"], ' ', $name));
}

function upload(Request $request)
{
    // ruleid: secreview.php.taint-file-upload
    move_uploaded_file($_FILES['avatar']['tmp_name'], 'uploads/' . basename($_FILES['avatar']['name']));
    $file = $request->file('avatar');
    // ruleid: secreview.php.taint-file-upload
    $file->storeAs('public/avatars', $file->getClientOriginalName());
    // ok: secreview.php.taint-file-upload
    $file->storeAs('public/avatars', $file->hashName());
    // ok: secreview.php.taint-file-upload
    move_uploaded_file($_FILES['avatar']['tmp_name'], 'uploads/' . bin2hex(random_bytes(16)) . '.png');
}
