// Test cases of the bundled OpenGrep rules: "ruleid" lines must match, "ok" lines must not.
// Request data appended to a StringBuilder.
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;

public class BuildersController : Controller
{
    private readonly SqlConnection _connection;

    public IActionResult Find([FromQuery] string name)
    {
        var query = new StringBuilder("SELECT * FROM Users WHERE Name = '");
        query.Append(name).Append("'");
        // ruleid: secreview.csharp.taint-sql
        using var command = new SqlCommand(query.ToString(), _connection);
        return Ok(command.ExecuteScalar());
    }
}
