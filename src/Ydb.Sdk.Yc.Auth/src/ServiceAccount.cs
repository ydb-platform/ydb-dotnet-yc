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

public class ServiceAccountProvider : IamProviderBase
{
    private static readonly TimeSpan JwtTtl = TimeSpan.FromHours(1);
    private readonly ILogger _logger;
    private readonly string _serviceAccountId;
    private readonly RsaSecurityKey _privateKey;

    public ServiceAccountProvider(string saFilePath, ILoggerFactory? loggerFactory = null)
        : base(loggerFactory)
    {
        loggerFactory ??= NullLoggerFactory.Instance;
        _logger = loggerFactory.CreateLogger<ServiceAccountProvider>();

        var saInfo = JsonSerializer.Deserialize<SaJsonInfo>(File.ReadAllText(saFilePath));
        if (saInfo == null) {
            throw new InvalidCredentialsException("Failed to parse service account file.");
        }
        saInfo.EnsureValid();

        _logger.LogDebug("Successfully parsed service account file.");

        _serviceAccountId = saInfo.service_account_id;

        using (var reader = new StringReader(saInfo.private_key)) {
            if (new PemReader(reader).ReadObject() is not RsaPrivateCrtKeyParameters parameters) {
                throw new InvalidCredentialsException("Failed to parse service account key.");
            }

            var rsaParams = DotNetUtilities.ToRSAParameters(parameters);
            _privateKey = new RsaSecurityKey(rsaParams) { KeyId = saInfo.id };
        }

        _logger.LogInformation("Successfully parsed service account key.");
    }

    protected override async Task<IamTokenData> FetchToken()
    {
        _logger.LogInformation("Fetching IAM token by service account key.");

        var services = new Yandex.Cloud.Generated.Services(new Yandex.Cloud.Sdk(new EmptyYcCredentialsProvider()));

        var request = new CreateIamTokenRequest
        {
            Jwt = MakeJwt()
        };

        var response = await services.Iam.IamTokenService.CreateAsync(request);

        var iamToken = new IamTokenData(
            token: response.IamToken,
            expiresAt: response.ExpiresAt.ToDateTime()
        );

        return iamToken;
    }

    private string MakeJwt()
    {
        var handler = new JsonWebTokenHandler();
        var now = DateTime.UtcNow;

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _serviceAccountId,
            Audience = YcAuth.DefaultAudience,
            IssuedAt = now,
            Expires = now.Add(JwtTtl),
            SigningCredentials = new SigningCredentials(_privateKey, SecurityAlgorithms.RsaSsaPssSha256),
        };

        return handler.CreateToken(descriptor);
    }

        private class SaJsonInfo
        {
            public string id { get; set; } = "";
            public string service_account_id { get; set; } = "";
            public string private_key { get; set; } = "";

        public void EnsureValid()
        {
            if (string.IsNullOrEmpty(id) ||
                string.IsNullOrEmpty(service_account_id) ||
                string.IsNullOrEmpty(private_key))
            {
                throw new InvalidCredentialsException("Invalid service account file.");
            }
        }
    }
}