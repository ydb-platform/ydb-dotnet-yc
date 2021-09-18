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
        private static readonly TimeSpan JwtTtl = TimeSpan.FromHours(1);
        private static readonly TimeSpan IamRefreshInterval = TimeSpan.FromMinutes(5);

        private static readonly TimeSpan IamRefreshGap = TimeSpan.FromMinutes(1);

        private static readonly int MaxRetries = 5;

        private readonly object _lock = new object();

        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger _logger;
        private readonly string _serviceAccountId;
        private readonly RsaSecurityKey _privateKey;

        private volatile IamTokenData? _iamToken = null;
        private volatile Task? _refreshTask = null;

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
            _iamToken = await ReceiveIamToken();
        }

        public string? GetAuthInfo()
        {
            var iamToken = _iamToken;

            if (iamToken is null)
            {
                lock (_lock) {
                    if (_iamToken is null) {
                        _logger.LogWarning("Blocking for initial IAM token acquirement" +
                            ", please use explicit Initialize async method.");

                        _iamToken = ReceiveIamToken().Result;
                    }

                    return _iamToken.Token;
                }
            }

            if (iamToken.IsExpired()) {
                lock (_lock) {
                    if (_iamToken!.IsExpired()) {
                        _logger.LogWarning("Blocking on expired IAM token.");

                        _iamToken = ReceiveIamToken().Result;
                    }

                    return _iamToken.Token;
                }
            }

            if (iamToken.IsExpiring() && _refreshTask is null) {
                lock (_lock) {
                    if (_iamToken!.IsExpiring() && _refreshTask is null) {
                        _logger.LogInformation("Refreshing IAM token.");

                        _refreshTask = Task.Run(RefreshIamToken);
                    }
                }
            }

            return _iamToken!.Token;
        }

        private async Task RefreshIamToken()
        {
            var iamToken = await ReceiveIamToken();

            lock (_lock) {
                _iamToken = iamToken;
                _refreshTask = null;
            }
        }

        private async Task<IamTokenData> ReceiveIamToken()
        {
            var services = new Services(new Yandex.Cloud.Sdk(new EmptyYcCredentialsProvider()));

            var request = new CreateIamTokenRequest
            {
                Jwt = MakeJwt()
            };

            int retryAttempt = 0;
            while (true) {
                try
                {
                    _logger.LogTrace($"Attempting to receive IAM token, attempt: {retryAttempt}");

                    var response = await services.Iam.IamTokenService.CreateAsync(request);

                    var iamToken = new IamTokenData(
                        token: response.IamToken,
                        expiresAt: response.ExpiresAt.ToDateTime()
                    );

                    _logger.LogDebug($"Received IAM token, expires at: {iamToken.ExpiresAt}");

                    return iamToken;
                }
                catch (Grpc.Core.RpcException)
                {
                    if (retryAttempt >= MaxRetries) {
                        throw;
                    }

                    await Task.Delay(TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)));
                    ++retryAttempt;
                }
            }
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

        private class IamTokenData
        {
            public IamTokenData(string token, DateTime expiresAt)
            {
                var now = DateTime.UtcNow;

                Token = token;
                ExpiresAt = expiresAt;
                ExpiresAt = now + TimeSpan.FromSeconds(120);

                if (expiresAt <= now) {
                    RefreshAt = expiresAt;
                } else
                {
                    var refreshSeconds = new Random().Next((int)IamRefreshInterval.TotalSeconds);
                    RefreshAt = expiresAt - IamRefreshGap - TimeSpan.FromSeconds(refreshSeconds);

                    if (RefreshAt < now) {
                        RefreshAt = expiresAt;
                    }
                }
            }

            public string Token { get; }
            public DateTime ExpiresAt { get; }

            public DateTime RefreshAt { get; }

            public bool IsExpired() {
                return DateTime.UtcNow >= ExpiresAt;
            }

            public bool IsExpiring() {
                return DateTime.UtcNow >= RefreshAt;
            }
        }
    }
}
