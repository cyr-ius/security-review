// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Log injection and regular expressions built from request data.
using System;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

public class LogsController : Controller
{
    private readonly ILogger<LogsController> _logger;

    public IActionResult Login([FromQuery] string user)
    {
        // ruleid: secreview.csharp.taint-log-injection
        _logger.LogWarning("Failed login for " + user);
        // ok: secreview.csharp.taint-log-injection
        _logger.LogWarning("Failed login for {User}", user.Replace("\n", "").Replace("\r", ""));
        return Ok();
    }

    public IActionResult Search([FromQuery] string term, [FromQuery] string text)
    {
        // ruleid: secreview.csharp.taint-regex-injection
        var found = Regex.IsMatch(text, term);
        // ruleid: secreview.csharp.taint-regex-injection
        var compiled = new Regex(term, RegexOptions.IgnoreCase);
        // ok: secreview.csharp.taint-regex-injection
        var timed = Regex.IsMatch(text, term, RegexOptions.None, TimeSpan.FromMilliseconds(100));
        // ok: secreview.csharp.taint-regex-injection
        var linear = new Regex(term, RegexOptions.NonBacktracking);
        // ok: secreview.csharp.taint-regex-injection
        var escaped = Regex.IsMatch(text, Regex.Escape(term));
        return Ok(found || compiled.IsMatch(text) || timed || linear.IsMatch(text) || escaped);
    }
}
