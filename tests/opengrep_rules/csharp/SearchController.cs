// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// XPath, LDAP, NoSQL, regular expressions, logs, uploads and Dynamic LINQ.
using System.Linq.Dynamic.Core;
using Microsoft.AspNetCore.Mvc;

public class SearchController : Controller
{
    public IActionResult Search(string filter, string sort, string name)
    {
        // ruleid: secreview.csharp.taint-expression-injection
        var users = _db.Users.Where(filter);
        // ruleid: secreview.csharp.taint-expression-injection
        users = users.OrderBy(sort);
        // ok: secreview.csharp.taint-expression-injection
        users = users.Where("Name == @0", name);
        // ok: secreview.csharp.taint-expression-injection
        users = users.Where(u => u.Name == name);
        return Ok(users);
    }
}
