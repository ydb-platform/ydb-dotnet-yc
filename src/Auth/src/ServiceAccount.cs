using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Yandex.Cloud.Generated;
using Yandex.Cloud.Iam.V1;
using Ydb.Sdk.Auth;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Logging.Abstractions;

namespace Ydb.Sdk.Yc
{
    public class ServiceAccountProvider : ICredentialsProvider
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger _logger;
        private readonly string _serviceAccountId;
        private readonly RsaSecurityKey _privateKey;
        private IamTokenData? _iamToken = null;

        public ServiceAccountProvider(string saFilePath, ILoggerFactory? loggerFactory = null)
        {
            _loggerFactory = loggerFactory ?? NullLoggerFactory.Instance;
            _logger = _loggerFactory.CreateLogger<ServiceAccountProvider>();

            var saInfo = JsonSerializer.Deserialize<SaJsonInfo>(File.ReadAllText(saFilePath));
            if (saInfo == null) {
                throw new InvalidCredentialsException("Failed to parse service account file.");
            }
            saInfo.EnsureValid();

            _serviceAccountId = saInfo.service_account_id;

            using (var reader = new StringReader(saInfo.private_key)) {
                var parameters = new PemReader(reader).ReadObject() as RsaPrivateCrtKeyParameters;
                if (parameters == null) {
                    throw new InvalidCredentialsException("Failed to parse service account key.");
                }

                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(parameters);
                _privateKey = new RsaSecurityKey(rsaParams) { KeyId = saInfo.id };
            }
        }

        public async Task Initialize()
        {
            var services = new Services(new Yandex.Cloud.Sdk(new EmptyYcCredentialsProvider()));

            var request = new CreateIamTokenRequest
            {
                Jwt = MakeJwt()
            };

            var response = await services.Iam.IamTokenService.CreateAsync(request);

            _iamToken = new IamTokenData(
                token: response.IamToken,
                expiresAt: response.ExpiresAt.ToDateTime()
            );

            _logger.LogDebug($"Received initial IAM token, expires at: {_iamToken.ExpiresAt}");
        }

        public string? GetAuthInfo()
        {
            if (_iamToken is null)
            {
                _logger.LogWarning("Blocking for initial token acquirement" +
                    ", please use explicit Initialize async method.");

                Initialize().Wait();
            }

            return _iamToken!.Token;
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
                    Expires = now.Add(YcAuth.DefaultTokenTtl),
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

        private class IamTokenData
        {
            public IamTokenData(string token, DateTime expiresAt)
            {
                Token = token;
                ExpiresAt = expiresAt;
            }

            public string Token { get; }
            public DateTime ExpiresAt { get; }
        }
    }
}
