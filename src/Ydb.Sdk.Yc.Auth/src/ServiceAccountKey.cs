using System.Text.Json.Serialization;

namespace Ydb.Sdk.Yc;

public class ServiceAccountKey
{
    [JsonConstructor]
    public ServiceAccountKey(string id, string serviceAccountId, string privateKey)
    {
        Id = id;
        ServiceAccountId = serviceAccountId;
        PrivateKey = privateKey;
    }

    [JsonRequired]
    [JsonPropertyName(name: "id")]
    public string Id { get; init; }

    [JsonRequired]
    [JsonPropertyName(name: "service_account_id")]
    public string ServiceAccountId { get; init; }

    [JsonRequired]
    [JsonPropertyName(name: "private_key")]
    public string PrivateKey { get; init; }
}