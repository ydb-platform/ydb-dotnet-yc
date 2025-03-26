using System;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Yandex.Cloud.Iam.V1;
using Ydb.Sdk.Auth;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ydb.Sdk.Yc;

public class ServiceAccountProvider : CachedCredentialsProvider
{
    public ServiceAccountProvider(string saFilePath, ILoggerFactory? loggerFactory = null) :
        base(
            new ServiceAccountAuthClient(saFilePath, loggerFactory),
            loggerFactory
        )
    {
    }
}

internal class ServiceAccountAuthClient : IAuthClient
{
    private static readonly TimeSpan JwtTtl = TimeSpan.FromHours(1);

    private readonly JsonWebTokenHandler _jsonWebTokenHandler = new();

    private readonly ILogger<ServiceAccountAuthClient> _logger;
    private readonly string _serviceAccountId;
    private readonly SigningCredentials _signingCredentials;

    public ServiceAccountAuthClient(string saFilePath, ILoggerFactory? loggerFactory = null)
    {
        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ServiceAccountAuthClient>();
        _serviceAccountId = saFilePath;

        var saFile = JsonSerializer.Deserialize<SaJsonInfo>(File.ReadAllText(saFilePath));
        if (saFile == null)
        {
            throw new FormatException("Failed to parse service account file");
        }

        _logger.LogDebug("Successfully parsed service account file");

        _serviceAccountId = saFile.ServiceAccountId;

        using (var reader = new StringReader(saFile.PrivateKey))
        {
            if (new PemReader(reader).ReadObject() is not RsaPrivateCrtKeyParameters parameters)
            {
                throw new FormatException("Failed to parse service account key");
            }

            var rsaParams = DotNetUtilities.ToRSAParameters(parameters);
            _signingCredentials = new SigningCredentials(new RsaSecurityKey(rsaParams) { KeyId = saFile.Id },
                SecurityAlgorithms.RsaSsaPssSha256);
        }

        _logger.LogInformation("Successfully parsed service account key");
    }

    public async Task<TokenResponse> FetchToken()
    {
        var st = Stopwatch.StartNew();
        var sdk = new Yandex.Cloud.Sdk(new EmptyYcCredentialsProvider());
        Console.WriteLine("Creating Yandex.Cloud.Sdk ms: " + st.ElapsedMilliseconds);

        _logger.LogInformation("Fetching IAM token by service account key.");

        var request = new CreateIamTokenRequest
        {
            Jwt = MakeJwt()
        };
        Console.WriteLine("Creating CreateIamTokenRequest ms: " + st.ElapsedMilliseconds);

        var response = await sdk.Services.Iam.IamTokenService.CreateAsync(request);

        _logger.LogInformation("Successfully fetched IAM token. ExpiredAt: {ExpiredAt}", response.ExpiresAt);

        return new TokenResponse(
            token: response.IamToken,
            expiredAt: response.ExpiresAt.ToDateTime()
        );
    }

    private string MakeJwt()
    {
        var now = DateTime.UtcNow;

        return _jsonWebTokenHandler.CreateToken(
            new SecurityTokenDescriptor
            {
                Issuer = _serviceAccountId,
                Audience = YcAuth.DefaultAudience,
                IssuedAt = now,
                Expires = now.Add(JwtTtl),
                SigningCredentials = _signingCredentials
            }
        );
    }

    private class SaJsonInfo
    {
        [JsonRequired]
        [JsonPropertyName(name: "id")]
        public string Id { get; init; } = "";

        [JsonRequired]
        [JsonPropertyName(name: "service_account_id")]
        public string ServiceAccountId { get; init; } = "";

        [JsonRequired]
        [JsonPropertyName(name: "private_key")]
        public string PrivateKey { get; init; } = "";
    }
}