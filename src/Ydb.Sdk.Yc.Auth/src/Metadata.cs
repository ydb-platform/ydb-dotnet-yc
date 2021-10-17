using System;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ydb.Sdk.Yc
{
    public class MetadataProvider : IamProviderBase
    {
        private readonly ILogger _logger;

        public MetadataProvider(ILoggerFactory? loggerFactory = null)
            : base(loggerFactory)
        {
            loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
            _logger = loggerFactory.CreateLogger<MetadataProvider>();
        }

        protected override async Task<IamTokenData> FetchToken()
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
            if (responseData == null) {
                throw new InvalidOperationException("Failed to parse metadata service response.");
            }

            var iamToken = new IamTokenData(
                token: responseData.access_token,
                expiresAt: DateTime.UtcNow + TimeSpan.FromSeconds(responseData.expires_in)
            );

            return iamToken;
        }

        private class ResponseData
        {
            public string access_token { get; set; } = "";

            public long expires_in { get; set; }
        }
    }
}
