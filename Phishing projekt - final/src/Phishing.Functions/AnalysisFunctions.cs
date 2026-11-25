using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Phishing.Core;
using Phishing.Functions.Storage;

namespace Phishing.Functions;

/// <summary>
/// Végpontok:
///   POST /api/analyze          e-mail elemzése és az eredmény mentése Cosmos DB-be
///   GET  /api/analyses/{id}    korábbi elemzés lekérdezése
///   GET  /api/analyses         legutóbbi elemzések listázása (?limit=20&amp;level=magas)
/// </summary>
public sealed class AnalysisFunctions
{
    private const int MaxBodyBytes = 256 * 1024;
    private static readonly string[] ValidLevels = { "alacsony", "közepes", "magas" };

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IAnalysisRepository _repository;
    private readonly ILogger<AnalysisFunctions> _logger;

    public AnalysisFunctions(IAnalysisRepository repository, ILogger<AnalysisFunctions> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    [Function("Analyze")]
    public async Task<IActionResult> Analyze(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "analyze")] HttpRequest req,
        CancellationToken ct)
    {
        // A törzset korlátozott méretig olvassuk be.
        var buffer = new MemoryStream();
        var chunk = new byte[8192];
        int read;
        while ((read = await req.Body.ReadAsync(chunk, ct)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > MaxBodyBytes)
                return Error(StatusCodes.Status413PayloadTooLarge, "A kérés túl nagy (max. 256 KB).");
        }
        buffer.Position = 0;

        EmailInput? email;
        try
        {
            email = await JsonSerializer.DeserializeAsync<EmailInput>(buffer, JsonOptions, ct);
        }
        catch (JsonException)
        {
            return Error(StatusCodes.Status400BadRequest, "Érvénytelen JSON.");
        }

        if (email is null
            || (string.IsNullOrWhiteSpace(email.Sender)
                && string.IsNullOrWhiteSpace(email.Subject)
                && string.IsNullOrWhiteSpace(email.Body)))
        {
            return Error(StatusCodes.Status400BadRequest,
                "Legalább a sender, subject vagy body mező szükséges.");
        }

        var result = PhishingAnalyzer.Analyze(email);
        var body = email.Body ?? "";

        var document = new AnalysisDocument
        {
            Id = Guid.NewGuid().ToString(),
            AnalyzedAt = DateTimeOffset.UtcNow,
            Sender = email.Sender ?? "",
            ReplyTo = email.ReplyTo ?? "",
            Subject = email.Subject ?? "",
            BodySha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body))).ToLowerInvariant(),
            BodyPreview = body.Length <= 200 ? body : body[..200],
            Attachments = email.Attachments ?? new List<string>(),
            RiskScore = result.RiskScore,
            RiskLevel = result.RiskLevel,
            Findings = result.Findings,
            AnalyzedUrls = result.AnalyzedUrls,
        };

        try
        {
            await _repository.SaveAsync(document, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Cosmos DB mentés sikertelen");
            return new ObjectResult(new { error = "Az eredmény mentése nem sikerült.", result })
            {
                StatusCode = StatusCodes.Status502BadGateway,
            };
        }

        return new ObjectResult(document) { StatusCode = StatusCodes.Status201Created };
    }

    [Function("GetAnalysis")]
    public async Task<IActionResult> GetAnalysis(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "analyses/{id}")] HttpRequest req,
        string id,
        CancellationToken ct)
    {
        try
        {
            var document = await _repository.GetAsync(id, ct);
            return document is null
                ? Error(StatusCodes.Status404NotFound, "Nem található.")
                : new OkObjectResult(document);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Cosmos DB lekérdezés sikertelen");
            return Error(StatusCodes.Status502BadGateway, "Adatbázis-hiba.");
        }
    }

    [Function("ListAnalyses")]
    public async Task<IActionResult> ListAnalyses(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "analyses")] HttpRequest req,
        CancellationToken ct)
    {
        var limit = 20;
        if (req.Query.TryGetValue("limit", out var limitValue)
            && !int.TryParse(limitValue.ToString(), out limit))
        {
            return Error(StatusCodes.Status400BadRequest, "A limit egész szám legyen.");
        }
        limit = Math.Clamp(limit, 1, 100);

        string? level = req.Query.TryGetValue("level", out var levelValue) && levelValue.Count > 0
            ? levelValue.ToString()
            : null;
        if (!string.IsNullOrEmpty(level) && !ValidLevels.Contains(level))
            return Error(StatusCodes.Status400BadRequest,
                "A level értéke: alacsony, közepes vagy magas.");
        if (string.IsNullOrEmpty(level)) level = null;

        try
        {
            var items = await _repository.ListAsync(limit, level, ct);
            return new OkObjectResult(new { count = items.Count, items });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Cosmos DB lekérdezés sikertelen");
            return Error(StatusCodes.Status502BadGateway, "Adatbázis-hiba.");
        }
    }

    private static ObjectResult Error(int status, string message) =>
        new(new { error = message }) { StatusCode = status };
}
