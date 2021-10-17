# Yandex.Cloud libraries for YDB

## Auth Library

[![Nuget](https://img.shields.io/nuget/v/Ydb.Sdk.Yc.Auth)](https://www.nuget.org/packages/Ydb.Sdk.Yc.Auth/)

### Installation

```
dotnet add package Ydb.Sdk.Yc.Auth
```
### Authentication

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

* `Ydb.Sdk.Yc.MetadataProvider`. Metadata service authentication, works inside Yandex Cloud VMs and Cloud Functions. Sample usage:

```c#
var metadataProvider = new MetadataProvider(loggerFactory: loggerFactory);

// Await initial IAM token.
await metadataProvider.Initialize();

var config = new DriverConfig(
    endpoint: endpoint, // Database endpoint, "grpcs://host:port"
    database: database, // Full database path
    credentials: metadataProvider
);
```

### Certificates

Library includes default Yandex Cloud server certificate, which is required for connectivity with dedicated YDB databases:

```c#
var cert = Ydb.Sdk.Yc.YcCerts.GetDefaultServerCertificate();

var config = new DriverConfig(
    endpoint: endpoint, // Database endpoint, "grpcs://host:port"
    database: database, // Full database path
    credentials: credentials, // Credentials provider, see above
    customServerCertificate: cert // Required for dedicated YDB dababases
);

```

