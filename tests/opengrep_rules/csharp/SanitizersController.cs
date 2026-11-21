// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data encoded in a URL whose host is fixed.
using System.Net;
using Microsoft.AspNetCore.Mvc;

public class SanitizersController : Controller
{
    private readonly HttpClient _http;

    public async Task<IActionResult> Profile([FromQuery] string user)
    {
        // ok: secreview.csharp.taint-ssrf
        var body = await _http.GetStringAsync("https://api.example.com/users/" + WebUtility.UrlEncode(user));
        return Content(body);
    }
}
