<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.

function sql($conn, $pdo, $request) {
    $id = $_GET['id'];
    $query = "SELECT * FROM users WHERE id = " . $id;
    // ruleid: secreview.php.taint-sql
    mysqli_query($conn, $query);
    $name = $request->input('name');
    // ruleid: secreview.php.taint-sql
    $pdo->query("SELECT * FROM users WHERE name = '$name'");
    // ruleid: secreview.php.taint-sql
    DB::select("SELECT * FROM users WHERE name = '" . $name . "'");
    $safe = intval($_GET['id']);
    // ok: secreview.php.taint-sql
    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $safe);
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
    // ok: secreview.php.taint-sql
    $stmt->execute([$name]);
    // ok: secreview.php.taint-sql
    DB::select("SELECT * FROM users WHERE name = ?", [$name]);
}

function command() {
    $host = $_POST['host'];
    // ruleid: secreview.php.taint-command
    $out = shell_exec("ping -c 1 " . $host);
    // ok: secreview.php.taint-command
    $out = shell_exec("ping -c 1 " . escapeshellarg($host));
    // ruleid: secreview.php.taint-code-eval
    eval($_POST['code']);
    $handler = $_GET['handler'];
    // ruleid: secreview.php.taint-code-eval
    call_user_func($handler, 'x');
    // ok: secreview.php.taint-code-eval
    call_user_func('strtoupper', $handler);
}

function cloneRepository() {
    $branch = $_POST['branch'];
    // ruleid: secreview.php.taint-argument-injection
    proc_open(['git', 'clone', '--branch', $branch, 'https://example.com/repo'], [], $pipes);
    // ok: secreview.php.taint-argument-injection
    proc_open(['git', 'clone', '--branch', 'main', 'https://example.com/repo'], [], $pipes);
    // ok: secreview.php.taint-argument-injection
    proc_open(['git', 'clone', '--', $branch, 'https://example.com/repo'], [], $pipes);
}

function files($request) {
    $page = $_GET['page'];
    // ruleid: secreview.php.taint-file-inclusion
    include $page . '.php';
    // ok: secreview.php.taint-file-inclusion
    include __DIR__ . '/pages/home.php';
    $name = $request->query->get('file');
    // ruleid: secreview.php.taint-path-traversal
    readfile('/var/www/uploads/' . $name);
    // ok: secreview.php.taint-path-traversal
    readfile('/var/www/uploads/' . basename($name));
}

function outgoing($client) {
    $url = $_GET['url'];
    // ruleid: secreview.php.taint-ssrf
    $ch = curl_init($url);
    // ruleid: secreview.php.taint-ssrf
    $client->request('GET', $url);
    // ok: secreview.php.taint-ssrf
    $client->request('GET', 'https://api.example.com/status', ['query' => ['q' => $url]]);
}

function page() {
    $name = $_GET['name'];
    // ruleid: secreview.php.taint-xss
    echo "<p>Hello " . $name . "</p>";
    // ok: secreview.php.taint-xss
    echo "<p>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</p>";
    // ruleid: secreview.php.taint-open-redirect
    header("Location: " . $_GET['next']);
    // ok: secreview.php.taint-open-redirect
    header("Location: /dashboard");
    // ruleid: secreview.php.taint-deserialization
    $cart = unserialize($_COOKIE['cart']);
    // ok: secreview.php.taint-deserialization
    $cart = json_decode($_COOKIE['cart'], true);
}

// False positives found on real projects (DVWA, BookStack)
function real_projects($request, $repo) {
    // ok: secreview.php.taint-path-traversal
    $input = json_decode(file_get_contents('php://input'), true);
    // ok: secreview.php.taint-sql
    $state = $request->query('state');
    $shelf = $repo->create($request->all());
    // ok: secreview.php.taint-open-redirect
    return redirect($shelf->getUrl());
}

function reset_link($request) {
    $token = $request->input('token');
    // ok: secreview.php.taint-open-redirect
    return redirect("/password/reset/{$token}");
}

function next_page($request) {
    // ruleid: secreview.php.taint-open-redirect
    return redirect($request->input('next'));
}
