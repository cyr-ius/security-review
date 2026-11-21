// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Mass assignment: the whole request, or an entity bound from it, saved as it is.
using Microsoft.AspNetCore.Mvc;

public class MassAssignmentController : Controller
{
    private readonly AppDbContext _db;

    public async Task<IActionResult> Create([FromBody] User user)
    {
        // ruleid: secreview.csharp.mass-assignment-bound-entity
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return Ok();
    }

    public async Task<IActionResult> Edit(int id)
    {
        var user = await _db.Users.FindAsync(id);
        // ruleid: secreview.csharp.mass-assignment-bound-entity
        await TryUpdateModelAsync(user);
        // ok: secreview.csharp.mass-assignment-bound-entity
        await TryUpdateModelAsync(user, "", u => u.Name, u => u.Email);
        return Ok();
    }

    public async Task<IActionResult> Register([FromBody] NewUser form)
    {
        var user = new User { Name = form.Name, Email = form.Email };
        // ok: secreview.csharp.mass-assignment-bound-entity
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return Ok();
    }
}
