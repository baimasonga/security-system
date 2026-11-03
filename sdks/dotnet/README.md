# Rokela .NET update metadata verifier

`Rokela.Updates` targets .NET 10. It verifies public update metadata with NSec
Ed25519; it never downloads or runs an installer. See
[ADR-034](../../docs/adr/ADR-034-dotnet-update-metadata.md) for the current boundary.

```csharp
using Rokela.Updates;

var verifier = new UpdateMetadataVerifier(independentlyPinnedRootJson);
var metadata = verifier.Verify(envelopeJson, "sierra-business", "windows-x64",
    "stable", DateTimeOffset.UtcNow);
// Authenticated metadata only: do not install or claim rollback protection.
```

Run on Linux or Windows:

```sh
dotnet test sdks/dotnet/Rokela.Updates.Tests
```

Fixtures in `docs/api/update-metadata-vectors.json` are also checked by the Node
SDK. Regenerate them only alongside protocol changes with
`node tools/gen-update-vectors.ts > docs/api/update-metadata-vectors.json`.
The generator outputs public keys and signed fixtures only. No deployment,
production keys or Business Admin update settings change in this slice.
