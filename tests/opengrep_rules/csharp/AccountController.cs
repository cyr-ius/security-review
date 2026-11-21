// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Password reset links built from the Host header.
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;

public class AccountController : Controller
{
    private readonly IEmailSender _emailSender;
    private readonly string _baseUrl;

    public async Task<IActionResult> ForgotPassword(string email, string code)
    {
        var callbackUrl = Url.Action("ResetPassword", "Account", new { code }, protocol: Request.Scheme);
        // ruleid: secreview.csharp.taint-host-header
        await _emailSender.SendEmailAsync(email, "Reset Password", $"Reset your password <a href='{callbackUrl}'>here</a>.");
        var fromHost = $"https://{Request.Host}/reset?code={code}";
        // ruleid: secreview.csharp.taint-host-header
        await _emailSender.SendEmailAsync(email, "Reset Password", fromHost);
        // ok: secreview.csharp.taint-host-header
        await _emailSender.SendEmailAsync(email, "Reset Password", $"{_baseUrl}/reset?code={code}");
        return View();
    }
}
