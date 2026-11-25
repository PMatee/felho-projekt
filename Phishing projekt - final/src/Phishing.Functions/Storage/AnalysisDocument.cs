using Phishing.Core;

namespace Phishing.Functions.Storage;

/// <summary>A Cosmos DB-ben tárolt dokumentum. A teljes levéltörzset nem tároljuk.</summary>
public sealed record AnalysisDocument
{
    public required string Id { get; init; }
    public required DateTimeOffset AnalyzedAt { get; init; }
    public string Sender { get; init; } = "";
    public string ReplyTo { get; init; } = "";
    public string Subject { get; init; } = "";

    /// <summary>A levéltörzs SHA-256 lenyomata (adatvédelmi okból a törzs maga nem kerül mentésre).</summary>
    public string BodySha256 { get; init; } = "";

    /// <summary>A levéltörzs első 200 karaktere.</summary>
    public string BodyPreview { get; init; } = "";

    public IReadOnlyList<string> Attachments { get; init; } = Array.Empty<string>();

    public required int RiskScore { get; init; }

    /// <summary>Partíciókulcs (/riskLevel): alacsony, közepes vagy magas.</summary>
    public required string RiskLevel { get; init; }

    public required IReadOnlyList<Finding> Findings { get; init; }
    public required IReadOnlyList<string> AnalyzedUrls { get; init; }
}

/// <summary>A listázáshoz használt rövid nézet.</summary>
public sealed record AnalysisSummary(
    string Id,
    DateTimeOffset AnalyzedAt,
    string Sender,
    string Subject,
    int RiskScore,
    string RiskLevel);
