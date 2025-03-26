using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Ydb.Sdk.Auth;

namespace Ydb.Sdk.Yc;

public class MetadataProvider : CachedCredentialsProvider
{
    public MetadataProvider(ILoggerFactory? loggerFactory = null)
        : base(new MetadataAuthClient(loggerFactory), loggerFactory)
    {
    }
}

internal class MetadataAuthClient : IAuthClient
{
    private readonly ILogger<MetadataAuthClient> _logger;

    public MetadataAuthClient(ILoggerFactory? loggerFactory = null)
    {
        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<MetadataAuthClient>();
    }

    public async Task<TokenResponse> FetchToken()
    {
        _logger.LogInformation("Fetching IAM token by service account key.");

        var client = new HttpClient();

        var request = new HttpRequestMessage(HttpMethod.Get, YcAuth.MetadataUrl);
        request.Headers.Add("Metadata-Flavor", "Google");

        var response = await client.SendAsync(request);
        if (response.StatusCode != HttpStatusCode.OK)
        {
            throw new HttpRequestException(
                $"Failed to fetch IAM token from metadata service, HTTP status code: {response.StatusCode}");
        }

        var content = await response.Content.ReadAsStringAsync();
        var responseData = JsonSerializer.Deserialize<ResponseData>(content);
        if (responseData == null)
        {
            throw new InvalidOperationException("Failed to parse metadata service response.");
        }

        var iamToken = new TokenResponse(
            token: responseData.AccessToken,
            expiredAt: DateTime.UtcNow + TimeSpan.FromSeconds(responseData.ExpiresIn)
        );

        return iamToken;
    }

    private class ResponseData
    {
        [JsonRequired]
        [JsonPropertyName(name: "access_token")]
        public string AccessToken { get; init; } = "";

        [JsonRequired]
        [JsonPropertyName(name: "expires_in")]
        public long ExpiresIn { get; init; }
    }
}