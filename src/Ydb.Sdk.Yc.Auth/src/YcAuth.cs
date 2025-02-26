using System;

namespace Ydb.Sdk.Yc
{
    internal static class YcAuth {
        public const string DefaultAudience = "https://iam.api.cloud.yandex.net/iam/v1/tokens";
        public const string MetadataUrl = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token";
    };

    internal class EmptyYcCredentialsProvider : Yandex.Cloud.Credentials.ICredentialsProvider
    {
        public string GetToken()
        {
            return "";
        }
    }
}
