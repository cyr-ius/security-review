// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
using System.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

public class WebhookController : Controller
{
    // ruleid: secreview.csharp.antiforgery-disabled
    [IgnoreAntiforgeryToken]
    public IActionResult Receive()
    {
        return Ok();
    }

    // ok: secreview.csharp.antiforgery-disabled
    [ValidateAntiForgeryToken]
    public IActionResult Save()
    {
        return Ok();
    }

    public bool Verify(string signature, string expectedSignature, byte[] mac, byte[] expectedMac)
    {
        // ruleid: secreview.csharp.non-constant-time-compare
        var same = signature == expectedSignature;
        // ruleid: secreview.csharp.non-constant-time-compare
        var bytes = mac.SequenceEqual(expectedMac);
        // ok: secreview.csharp.non-constant-time-compare
        var safe = CryptographicOperations.FixedTimeEquals(mac, expectedMac);
        // ok: secreview.csharp.non-constant-time-compare
        var missing = signature == null;
        return same && bytes && safe && missing;
    }
}
