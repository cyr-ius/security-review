// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data passed as an argument of a program (option injection).
using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

public class MirrorController : Controller
{
    public IActionResult Mirror([FromForm] string url)
    {
        // ruleid: secreview.csharp.taint-argument-injection
        Process.Start("git", new[] { "clone", url, "/srv/mirror" });
        var info = new ProcessStartInfo("ssh");
        // ruleid: secreview.csharp.taint-argument-injection
        info.ArgumentList.Add(url);
        // ok: secreview.csharp.taint-argument-injection
        Process.Start("git", new[] { "clone", "--", url, "/srv/mirror" });
        // ok: secreview.csharp.taint-argument-injection
        Process.Start("git", new[] { "clone", "--branch=" + url, "https://example.com/repo" });
        // ok: secreview.csharp.taint-argument-injection
        Process.Start("/opt/tools/report", new[] { "run", url });
        return Ok();
    }
}
