// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data naming a module, a class or a method reached by reflection.
using System;
using Microsoft.AspNetCore.Mvc;

public class ReflectionController : Controller
{
    public IActionResult Run(string type, string method)
    {
        // ruleid: secreview.csharp.taint-unsafe-reflection
        var handler = Type.GetType("App.Handlers." + type);
        // ruleid: secreview.csharp.taint-unsafe-reflection
        var member = handler.GetMethod(method);
        // ok: secreview.csharp.taint-unsafe-reflection
        var fixedType = Type.GetType("App.Handlers.Export");
        return Ok(member.Invoke(null, null));
    }
}
