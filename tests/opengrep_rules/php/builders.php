<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data added to an array.

function columns($pdo) {
    $columns = ['id'];
    array_push($columns, $_GET['column']);
    // ruleid: secreview.php.taint-sql
    $pdo->query("SELECT " . implode(", ", $columns) . " FROM users");
}
