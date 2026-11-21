// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Minimal API handlers receive request data as lambda parameters.
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

public static class MinimalApi
{
    public static void Map(WebApplication app)
    {
        // ruleid: secreview.csharp.taint-sql
        app.MapGet("/users", (string name, AppDbContext db) => db.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'"));

        app.MapPost("/users", async ([FromBody] UserDto user, AppDbContext db) =>
        {
            // ruleid: secreview.csharp.taint-sql
            await db.Database.ExecuteSqlRawAsync("DELETE FROM Users WHERE Name = '" + user.Name + "'");
        });

        // ok: secreview.csharp.taint-sql
        app.MapGet("/users/{id}", (int id, AppDbContext db) => db.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Id = " + id));
    }
}
