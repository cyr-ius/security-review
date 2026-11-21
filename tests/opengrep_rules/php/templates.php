<?php
// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data compiled as a template; request data naming a class, a method or a function.
function preview(Twig\Environment $twig, Smarty $smarty)
{
    $body = $_POST['body'];
    // ruleid: secreview.php.taint-template-injection
    $template = $twig->createTemplate($body);
    // ruleid: secreview.php.taint-template-injection
    $smarty->fetch('string:' . $body);
    // ruleid: secreview.php.taint-template-injection
    echo Blade::render($body, ['user' => 'x']);
    // ok: secreview.php.taint-template-injection
    echo $twig->render('preview.html.twig', ['body' => $body]);
    // ok: secreview.php.taint-template-injection
    $smarty->fetch('preview.tpl');
}

function dispatch($service)
{
    $class = $_GET['class'];
    $method = $_GET['method'];
    $function = $_GET['function'];
    // ruleid: secreview.php.taint-unsafe-reflection
    $handler = new $class();
    // ruleid: secreview.php.taint-unsafe-reflection
    $service->$method();
    // ruleid: secreview.php.taint-unsafe-reflection
    $function();
    // ok: secreview.php.taint-unsafe-reflection
    $service->run($method);
    // ok: secreview.php.taint-unsafe-reflection
    strtolower($function);
}
