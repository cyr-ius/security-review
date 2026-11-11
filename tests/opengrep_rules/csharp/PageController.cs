// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
using System.Net;
using System.Security.Authentication;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class PageController : ControllerBase
{
    [HttpGet("greet")]
    public IActionResult Greet([FromQuery] string name)
    {
        // ruleid: secreview.csharp.taint-xss
        return Content("<p>Hello " + name + "</p>", "text/html");
    }

    [HttpGet("greet-safe")]
    public IActionResult GreetSafe([FromQuery] string name)
    {
        // ok: secreview.csharp.taint-xss
        return Content("<p>Hello " + HtmlEncoder.Default.Encode(name) + "</p>", "text/html");
    }

    [HttpPost("login")]
    public IActionResult Login()
    {
        // ruleid: secreview.csharp.cookie-insecure
        Response.Cookies.Append("session", "value", new CookieOptions { Secure = false, HttpOnly = true });
        // ok: secreview.csharp.cookie-insecure
        Response.Cookies.Append("session", "value", new CookieOptions { Secure = true, HttpOnly = true });
        return Ok();
    }

    public void Tls(SslServerOptions options)
    {
        // ruleid: secreview.csharp.tls-weak-version
        options.EnabledSslProtocols = SslProtocols.Tls11 | SslProtocols.Tls12;
        // ok: secreview.csharp.tls-weak-version
        options.EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
    }
}
