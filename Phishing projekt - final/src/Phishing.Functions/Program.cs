using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Azure.Cosmos;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Phishing.Functions.Storage;

var host = new HostBuilder()
    .ConfigureFunctionsWebApplication()
    .ConfigureServices(services =>
    {
        // Egyetlen CosmosClient példány az egész alkalmazásra (az SDK ezt javasolja).
        services.AddSingleton(sp =>
        {
            var config = sp.GetRequiredService<IConfiguration>();
            var options = new CosmosClientOptions
            {
                ApplicationName = "PhishingAnalyzer",
                UseSystemTextJsonSerializerWithOptions = new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                },
            };

            // Helyi fejlesztés: Cosmos DB emulátor (docker-compose). Csak COSMOS_EMULATOR=true esetén aktív.
            if (string.Equals(config["COSMOS_EMULATOR"], "true", StringComparison.OrdinalIgnoreCase))
            {
                options.ConnectionMode = ConnectionMode.Gateway;
                options.LimitToEndpoint = true;
                // Az emulátor önaláírt tanúsítványt használhat; ezt éles környezetben SOHA ne kapcsold be.
                options.HttpClientFactory = () => new HttpClient(new HttpClientHandler
                {
                    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
                });
            }

            var connectionString = config["COSMOS_CONNECTION_STRING"];
            if (!string.IsNullOrWhiteSpace(connectionString))
                return new CosmosClient(connectionString, options);

            var endpoint = config["COSMOS_ENDPOINT"]
                ?? throw new InvalidOperationException("Hiányzik a COSMOS_ENDPOINT beállítás.");
            var key = config["COSMOS_KEY"]
                ?? throw new InvalidOperationException("Hiányzik a COSMOS_KEY beállítás.");
            return new CosmosClient(endpoint, key, options);
        });

        services.AddSingleton<IAnalysisRepository, CosmosAnalysisRepository>();
    })
    .Build();

host.Run();
