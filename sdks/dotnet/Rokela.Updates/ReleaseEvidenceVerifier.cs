using System.Security.Cryptography;
using System.Text.Json;

namespace Rokela.Updates;

public sealed record VerifiedReleaseEvidence(string BuilderId, string BuildType, int Components);

/// <summary>Signer-endorsed evidence, not an independent attestation of the build environment.</summary>
public static class ReleaseEvidenceVerifier
{
  public const int MaximumBytes = 2 * 1024 * 1024;

  public static VerifiedReleaseEvidence Verify(VerifiedUpdateMetadata metadata, byte[] sbom, byte[] provenance,
      IReadOnlyCollection<string> trustedBuilders)
  {
    if (trustedBuilders.Count == 0) Fail("no trusted builders");
    if (sbom.Length > MaximumBytes || provenance.Length > MaximumBytes) Fail("evidence size");
    if (Hash(sbom) != metadata.SbomSha256 || Hash(provenance) != metadata.ProvenanceSha256) Fail("evidence digest");
    try
    {
      using var bomDoc = Parse(sbom); var bom = bomDoc.RootElement;
      if (Text(bom, "bomFormat") != "CycloneDX" || Text(bom, "specVersion") is not ("1.4" or "1.5" or "1.6"))
        Fail("SBOM format");
      var hashes = Get(Get(Get(bom, "metadata"), "component"), "hashes");
      if (hashes.ValueKind != JsonValueKind.Array || !hashes.EnumerateArray().Any(h =>
          Text(h, "alg") == "SHA-256" && Text(h, "content") == metadata.Sha256)) Fail("SBOM artifact");
      int components = 0;
      if (bom.TryGetProperty("components", out var c))
      {
        if (c.ValueKind != JsonValueKind.Array) Fail("SBOM components");
        components = c.GetArrayLength();
      }
      using var statement = Parse(provenance); var st = statement.RootElement;
      if (Text(st, "_type") != "https://in-toto.io/Statement/v1" ||
          Text(st, "predicateType") != "https://slsa.dev/provenance/v1") Fail("provenance format");
      var subject = Get(st, "subject");
      if (subject.ValueKind != JsonValueKind.Array || subject.GetArrayLength() != 1 ||
          Text(Get(subject[0], "digest"), "sha256") != metadata.Sha256) Fail("provenance artifact");
      var predicate = Get(st, "predicate");
      string buildType = Text(Get(predicate, "buildDefinition"), "buildType");
      string builder = Text(Get(Get(predicate, "runDetails"), "builder"), "id");
      if (buildType.Length is < 1 or > 2048 || !trustedBuilders.Contains(builder, StringComparer.Ordinal)) Fail("builder policy");
      return new(builder, buildType, components);
    }
    catch (Exception e) when (e is JsonException or InvalidOperationException or KeyNotFoundException)
    {
      throw new UpdateVerificationException("malformed release evidence");
    }
  }

  private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
  private static JsonElement Get(JsonElement obj, string property)
  {
    if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(property, out var result))
      throw new UpdateVerificationException("evidence shape");
    return result;
  }
  private static string Text(JsonElement obj, string property)
  {
    var value = Get(obj, property);
    if (value.ValueKind != JsonValueKind.String) throw new UpdateVerificationException("evidence text");
    return value.GetString()!;
  }
  private static JsonDocument Parse(byte[] bytes)
  {
    var doc = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
    try
    {
      if (doc.RootElement.ValueKind != JsonValueKind.Object) Fail("evidence object");
      Unique(doc.RootElement);
      return doc;
    }
    catch { doc.Dispose(); throw; }
  }
  private static void Unique(JsonElement value)
  {
    if (value.ValueKind == JsonValueKind.Object)
    {
      var names = new HashSet<string>(StringComparer.Ordinal);
      foreach (var item in value.EnumerateObject())
      {
        if (!names.Add(item.Name)) Fail("duplicate evidence field");
        Unique(item.Value);
      }
    }
    else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
  }
  private static void Fail(string reason) => throw new UpdateVerificationException(reason);
}
