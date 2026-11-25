using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;

namespace Phishing.Functions;

/// <summary>
/// A webes felület kiszolgálása: GET /api/ui
/// Az oldal és az API-végpontok azonos eredetűek (nincs CORS), a felületen nem kell kulcsot megadni.
/// </summary>
public sealed class UiFunction
{
    private static readonly Lazy<string> Html = new(() =>
    {
        using var stream = typeof(UiFunction).Assembly.GetManifestResourceStream("index.html")
            ?? throw new InvalidOperationException("A beágyazott index.html nem található.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    });

    [Function("Ui")]
    public IActionResult Run(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "ui")] HttpRequest req)
    {
        var headers = req.HttpContext.Response.Headers;
        headers["X-Content-Type-Options"] = "nosniff";
        headers["Content-Security-Policy"] =
            "default-src 'none'; script-src 'unsafe-inline'; " +
            "style-src 'unsafe-inline' https://cdnjs.cloudflare.com; img-src data:; " +
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

        return new ContentResult
        {
            Content = Html.Value,
            ContentType = "text/html; charset=utf-8",
            StatusCode = StatusCodes.Status200OK,
        };
    }
}
