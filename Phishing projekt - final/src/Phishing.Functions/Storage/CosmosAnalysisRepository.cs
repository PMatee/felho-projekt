using Microsoft.Azure.Cosmos;
using Microsoft.Extensions.Configuration;

namespace Phishing.Functions.Storage;

public interface IAnalysisRepository
{
    Task SaveAsync(AnalysisDocument document, CancellationToken ct);
    Task<AnalysisDocument?> GetAsync(string id, CancellationToken ct);
    Task<IReadOnlyList<AnalysisSummary>> ListAsync(int limit, string? level, CancellationToken ct);
}

public sealed class CosmosAnalysisRepository : IAnalysisRepository
{
    private readonly Lazy<Task<Container>> _container;

    public CosmosAnalysisRepository(CosmosClient client, IConfiguration config)
    {
        var databaseName = config["COSMOS_DATABASE"] ?? "PhishingDb";
        var containerName = config["COSMOS_CONTAINER"] ?? "Analyses";

        // Lusta inicializálás: az adatbázis és a konténer az első használatkor jön létre.
        _container = new Lazy<Task<Container>>(async () =>
        {
            var db = await client.CreateDatabaseIfNotExistsAsync(databaseName);
            var response = await db.Database.CreateContainerIfNotExistsAsync(
                new ContainerProperties(containerName, "/riskLevel"));
            return response.Container;
        });
    }

    public async Task SaveAsync(AnalysisDocument document, CancellationToken ct)
    {
        var container = await _container.Value;
        await container.CreateItemAsync(document, new PartitionKey(document.RiskLevel), cancellationToken: ct);
    }

    public async Task<AnalysisDocument?> GetAsync(string id, CancellationToken ct)
    {
        // A partíciókulcs (riskLevel) ismeretlen, ezért lekérdezéssel keresünk.
        var container = await _container.Value;
        var query = new QueryDefinition("SELECT * FROM c WHERE c.id = @id").WithParameter("@id", id);

        using var iterator = container.GetItemQueryIterator<AnalysisDocument>(query);
        while (iterator.HasMoreResults)
        {
            var page = await iterator.ReadNextAsync(ct);
            var item = page.FirstOrDefault();
            if (item is not null) return item;
        }
        return null;
    }

    public async Task<IReadOnlyList<AnalysisSummary>> ListAsync(int limit, string? level, CancellationToken ct)
    {
        var container = await _container.Value;

        var sql = "SELECT c.id, c.analyzedAt, c.sender, c.subject, c.riskScore, c.riskLevel FROM c";
        if (level is not null) sql += " WHERE c.riskLevel = @level";
        sql += " ORDER BY c.analyzedAt DESC OFFSET 0 LIMIT @limit";

        var query = new QueryDefinition(sql).WithParameter("@limit", limit);
        if (level is not null) query = query.WithParameter("@level", level);

        var results = new List<AnalysisSummary>();
        using var iterator = container.GetItemQueryIterator<AnalysisSummary>(query);
        while (iterator.HasMoreResults)
        {
            var page = await iterator.ReadNextAsync(ct);
            results.AddRange(page);
        }
        return results;
    }
}
