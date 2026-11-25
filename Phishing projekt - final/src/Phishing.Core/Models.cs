using System.Text.Json.Serialization;

namespace Phishing.Core;

/// <summary>Az elemzendő e-mail leírása. Minden mező opcionális.</summary>
public sealed record EmailInput
{
    public string? Sender { get; init; }

    [JsonPropertyName("reply_to")]
    public string? ReplyTo { get; init; }

    public string? Subject { get; init; }

    /// <summary>Szöveges vagy HTML levéltörzs.</summary>
    public string? Body { get; init; }

    public List<string>? Urls { get; init; }

    /// <summary>Mellékletek fájlnevei.</summary>
    public List<string>? Attachments { get; init; }

    /// <summary>Hitelesítési eredmények: spf, dkim, dmarc ("pass", "fail", ...).</summary>
    public Dictionary<string, string>? Auth { get; init; }
}

/// <summary>Egy felismert gyanús jellemző.</summary>
public sealed record Finding(string Rule, int Points, string Description, string Evidence);

/// <summary>Az elemzés eredménye.</summary>
public sealed record AnalysisResult(
    int RiskScore,
    string RiskLevel,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<string> AnalyzedUrls);
