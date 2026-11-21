<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
use Symfony\Component\Process\Process;

function mirror()
{
    $url = $_POST['url'];
    // ruleid: secreview.php.taint-argument-injection
    exec('git clone ' . escapeshellarg($url) . ' /srv/mirror');
    // ruleid: secreview.php.taint-argument-injection
    $process = new Process(['git', 'clone', $url, '/srv/mirror']);
    // ruleid: secreview.php.taint-argument-injection
    proc_open(['curl', '-s', $url], [], $pipes);
    // ok: secreview.php.taint-argument-injection
    exec('git clone -- ' . escapeshellarg($url) . ' /srv/mirror');
    // ok: secreview.php.taint-argument-injection
    $process = new Process(['git', 'clone', '--', $url, '/srv/mirror']);
    // ok: secreview.php.taint-argument-injection
    $process = new Process(['/opt/tools/report', $url]);
}
