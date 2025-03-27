using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.FileProviders;

namespace Ydb.Sdk.Yc;

public static class YcCerts
{
    public static X509Certificate2Collection GetYcServerCertificates()
    {
        var embeddedProvider = new EmbeddedFileProvider(Assembly.GetExecutingAssembly(), "");

        using var stream = embeddedProvider.GetFileInfo("Ydb.Sdk.Yc.YandexAllCAs.pkcs").CreateReadStream();
        using var memoryStream = new MemoryStream();
        stream.CopyTo(memoryStream);

        var collection = new X509Certificate2Collection();
        collection.Import(memoryStream.ToArray(), "yandex", X509KeyStorageFlags.Exportable);

        return collection;
    }
}