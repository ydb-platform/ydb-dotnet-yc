# Yandex.Cloud libraries for YDB

## Authentication

[![Nuget](https://img.shields.io/nuget/v/Ydb.Sdk.Yc.Auth)](https://www.nuget.org/packages/Ydb.Sdk.Yc.Auth/)

Supported Yandex.Cloud authentication methods:
* `Ydb.Sdk.Yc.ServiceAccountProvider`. Service account authentication, sample usage:

```c#
var saProvider = new ServiceAccountProvider(
    saFilePath: file, // Path to file with service account JSON info
    loggerFactory: loggerFactory);

// Await initial IAM token.
await saProvider.Initialize();

var config = new DriverConfig(
    endpoint: endpoint, // Database endpoint, "grpcs://host:port"
    database: database, // Full database path
    credentials: saProvider
);

using var driver = new Driver(
    config: config,
    loggerFactory: loggerFactory
);

await driver.Initialize(); // Make sure to await driver initialization
```
