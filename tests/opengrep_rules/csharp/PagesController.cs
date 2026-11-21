// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data choosing the view or the template rendered.
using Microsoft.AspNetCore.Mvc;

public class PagesController : Controller
{
    public IActionResult Show(string page)
    {
        // ruleid: secreview.csharp.taint-view-injection
        return View(page);
    }

    public IActionResult Help(string topic)
    {
        // ok: secreview.csharp.taint-view-injection
        return View("Help", topic);
    }
}
