using System;

namespace Ydb.Sdk.Yc
{
    internal static class YcAuth {
        public static readonly string DefaultAudience = "https://iam.api.cloud.yandex.net/iam/v1/tokens";
        public static readonly string DefaultEndpoint = "iam.api.cloud.yandex.net:443";
    };

    internal class EmptyYcCredentialsProvider : Yandex.Cloud.Credentials.ICredentialsProvider
    {
        public string GetToken()
        {
            return "";
        }
    }
}
