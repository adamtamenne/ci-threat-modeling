using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

public class TestController : Controller
{
    [HttpPost]
    public IActionResult Search(string query)
    {
        string sql = "SELECT * FROM Users WHERE name = '" + query + "'";
        using var cmd = new SqliteCommand(sql, null);
        using var reader = cmd.ExecuteReader();
        return View();
    }

    [HttpGet]
    [AllowAnonymous]
    public IActionResult AdminPanel()
    {
        var connectionString = "Server=db;Password=SuperSecret123!";
        return Ok(connectionString);
    }
}
