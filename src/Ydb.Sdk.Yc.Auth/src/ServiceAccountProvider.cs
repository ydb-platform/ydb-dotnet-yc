using System;
using System.IO;
using System.Text.Json;
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
        base(new ServiceAccountAuthClient(saFilePath, loggerFactory), loggerFactory)
    {
    }

    public ServiceAccountProvider(ServiceAccountKey serviceAccountKey, ILoggerFactory? loggerFactory = null)
        : base(new ServiceAccountAuthClient(serviceAccountKey, loggerFactory))
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

    public ServiceAccountAuthClient(string saFilePath, ILoggerFactory? loggerFactory = null) :
        this(JsonSerializer.Deserialize<ServiceAccountKey>(File.ReadAllText(saFilePath))
             ?? throw new FormatException("Failed to parse service account file"), loggerFactory)
    {
    }

    public ServiceAccountAuthClient(ServiceAccountKey serviceAccountKey, ILoggerFactory? loggerFactory = null)
    {
        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ServiceAccountAuthClient>();

        _serviceAccountId = serviceAccountKey.ServiceAccountId;

        using var reader = new StringReader(serviceAccountKey.PrivateKey);
        if (new PemReader(reader).ReadObject() is not RsaPrivateCrtKeyParameters parameters)
        {
            throw new FormatException("Failed to parse service account key");
        }

        var rsaParams = DotNetUtilities.ToRSAParameters(parameters);
        _signingCredentials = new SigningCredentials(new RsaSecurityKey(rsaParams) { KeyId = serviceAccountKey.Id },
            SecurityAlgorithms.RsaSsaPssSha256);

        _logger.LogInformation("Successfully parsed service account key");
    }

    public async Task<TokenResponse> FetchToken()
    {
        var sdk = new Yandex.Cloud.Sdk(new EmptyYcCredentialsProvider());

        _logger.LogInformation("Fetching IAM token by service account key.");

        var request = new CreateIamTokenRequest
        {
            Jwt = MakeJwt()
        };

        var response = await sdk.Services.Iam.IamTokenService.CreateAsync(request);

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
}