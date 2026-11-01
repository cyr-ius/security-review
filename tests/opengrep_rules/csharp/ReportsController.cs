// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
using System.Diagnostics;
using System.Net.Http;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

[ApiController]
public class ReportsController : ControllerBase
{
    private readonly AppDbContext _db;
    private readonly HttpClient _http;
    private readonly SqlConnection _connection;

    [HttpGet("reports")]
    public IActionResult List([FromQuery] string owner, [FromQuery] string id)
    {
        // ruleid: secreview.csharp.taint-sql
        var command = new SqlCommand("SELECT * FROM Reports WHERE Owner = '" + owner + "'", _connection);
        // ruleid: secreview.csharp.taint-sql
        var reports = _db.Reports.FromSqlRaw($"SELECT * FROM Reports WHERE Owner = '{owner}'").ToList();
        // ok: secreview.csharp.taint-sql
        var safe = _db.Reports.FromSqlRaw("SELECT * FROM Reports WHERE Owner = {0}", owner).ToList();
        // ok: secreview.csharp.taint-sql
        var byId = new SqlCommand("SELECT * FROM Reports WHERE Id = " + int.Parse(id), _connection);
        return Ok(reports);
    }

    [HttpPost("convert")]
    public IActionResult Convert(string format)
    {
        // ruleid: secreview.csharp.taint-command
        Process.Start("/bin/sh", "-c \"convert report.pdf report." + format + "\"");
        // ok: secreview.csharp.taint-command
        Process.Start("/usr/bin/convert", "report.pdf report.png");
        return Ok();
    }

    [HttpGet("files/{name}")]
    public IActionResult Download([FromRoute] string name)
    {
        // ruleid: secreview.csharp.taint-path-traversal
        var bytes = System.IO.File.ReadAllBytes(System.IO.Path.Combine("/srv/files", name));
        // ok: secreview.csharp.taint-path-traversal
        var safe = System.IO.File.ReadAllBytes(System.IO.Path.Combine("/srv/files", System.IO.Path.GetFileName(name)));
        return File(bytes, "application/octet-stream");
    }

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery(Name = "url")] string url)
    {
        // ruleid: secreview.csharp.taint-ssrf
        var body = await _http.GetStringAsync(url);
        // ok: secreview.csharp.taint-ssrf
        var status = await _http.GetStringAsync("https://api.example.com/status?q=" + Uri.EscapeDataString(url));
        return Ok(body + status);
    }

    [HttpGet("login")]
    public IActionResult Login(string returnUrl)
    {
        if (Url.IsLocalUrl(returnUrl))
        {
            // ok: secreview.csharp.taint-open-redirect
            return Redirect(returnUrl);
        }
        // ruleid: secreview.csharp.taint-open-redirect
        return Redirect(returnUrl);
    }

    private void Helper(string owner)
    {
        // ok: secreview.csharp.taint-sql
        var command = new SqlCommand("SELECT * FROM Reports WHERE Owner = '" + owner + "'", _connection);
    }
}

public class Security
{
    public object Load(System.IO.Stream stream)
    {
        // ruleid: secreview.csharp.unsafe-deserialization
        var formatter = new BinaryFormatter();
        // ruleid: secreview.csharp.unsafe-deserialization
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        // ok: secreview.csharp.unsafe-deserialization
        var none = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.None };
        return formatter.Deserialize(stream);
    }

    public HttpClient Client()
    {
        var handler = new HttpClientHandler();
        // ruleid: secreview.csharp.certificate-validation-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
        // ok: secreview.csharp.certificate-validation-disabled
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == System.Net.Security.SslPolicyErrors.None;
        return new HttpClient(handler);
    }

    public TokenValidationParameters Tokens()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            // ruleid: secreview.csharp.jwt-validation-disabled
            ValidateLifetime = false,
            // ok: secreview.csharp.jwt-validation-disabled
            ValidateAudience = true,
        };
    }

    public byte[] Digest(byte[] data)
    {
        // ruleid: secreview.csharp.weak-crypto
        using var md5 = MD5.Create();
        // ok: secreview.csharp.weak-crypto
        return SHA256.HashData(data);
    }

    public XmlReaderSettings Xml()
    {
        // ruleid: secreview.csharp.xml-dtd-enabled
        var unsafeSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };
        // ok: secreview.csharp.xml-dtd-enabled
        return new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit };
    }

    public IHtmlContent Banner(string text)
    {
        // ruleid: secreview.csharp.html-encoding-bypassed
        var html = new HtmlString("<b>" + text + "</b>");
        // ok: secreview.csharp.html-encoding-bypassed
        return new HtmlString("<b>static</b>");
    }

    public void Cors(Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder policy)
    {
        // ruleid: secreview.csharp.cors-any-origin-credentials
        policy.SetIsOriginAllowed(origin => true).AllowAnyHeader().AllowCredentials();
        // ok: secreview.csharp.cors-any-origin-credentials
        policy.WithOrigins("https://app.example.com").AllowCredentials();
    }
}
