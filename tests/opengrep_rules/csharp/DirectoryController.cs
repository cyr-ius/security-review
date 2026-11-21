// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// LDAP, MongoDB, scripting and templates fed with request data.
using System.DirectoryServices;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.CSharp.Scripting;
using MongoDB.Bson;
using MongoDB.Driver;
using Scriban;

public class DirectoryController : Controller
{
    private readonly IMongoCollection<BsonDocument> _users;

    public IActionResult Find([FromQuery] string user)
    {
        // ruleid: secreview.csharp.taint-ldap-injection
        var searcher = new DirectorySearcher("(uid=" + user + ")");
        // ok: secreview.csharp.taint-ldap-injection
        var fixedSearcher = new DirectorySearcher("(objectClass=person)");
        // ruleid: secreview.csharp.taint-ldap-injection
        fixedSearcher.Filter = $"(mail={user})";
        return Ok(searcher.FindOne());
    }

    public IActionResult Query([FromQuery] string filter, [FromQuery] string name)
    {
        // ruleid: secreview.csharp.taint-nosql-injection
        var parsed = BsonDocument.Parse(filter);
        // ok: secreview.csharp.taint-nosql-injection
        var safe = Builders<BsonDocument>.Filter.Eq("name", name);
        return Ok(_users.Find(parsed).ToList().Count + _users.Find(safe).ToList().Count);
    }

    public async Task<IActionResult> Compute([FromQuery] string expression, [FromQuery] int count)
    {
        // ruleid: secreview.csharp.taint-code-eval
        var result = await CSharpScript.EvaluateAsync(expression);
        // ok: secreview.csharp.taint-code-eval
        var fixedResult = await CSharpScript.EvaluateAsync("1 + " + count);
        return Ok(result + fixedResult);
    }

    public IActionResult Render([FromQuery] string template, [FromQuery] string name)
    {
        // ruleid: secreview.csharp.taint-template-injection
        var custom = Template.Parse(template);
        // ok: secreview.csharp.taint-template-injection
        var fixedTemplate = Template.Parse("Hello {{ name }}");
        return Content(custom.Render() + fixedTemplate.Render(new { name }));
    }
}
