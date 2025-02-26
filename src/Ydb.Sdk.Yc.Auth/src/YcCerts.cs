using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.FileProviders;

namespace Ydb.Sdk.Yc
{
    public static class YcCerts {
        public static X509Certificate2 GetDefaultServerCertificate() {
            var embeddedProvider = new EmbeddedFileProvider(Assembly.GetExecutingAssembly(), "");

            using var stream = embeddedProvider.GetFileInfo("yc_default.pem").CreateReadStream();
            using var memoryStream = new MemoryStream();
            stream.CopyTo(memoryStream);
            return new X509Certificate2(memoryStream.ToArray());
        }
    };
}
