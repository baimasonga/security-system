using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Rokela.Updates;
using Xunit;

internal sealed class EvidenceFixture : IDisposable
{
  public TrustFixture Trust { get; } = new();
  public byte[] Artifact { get; }
  public EvidenceFixture(byte[]? artifact = null) => Artifact = artifact?.ToArray() ?? Enumerable.Repeat((byte)42, 1234).ToArray();
  public static string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();
  public const string Builder = "https://build.example/approved";
  public byte[] Sbom => Encoding.UTF8.GetBytes(SbomNode().ToJsonString());
  public byte[] Provenance => Encoding.UTF8.GetBytes(ProvenanceNode().ToJsonString());
  public JsonNode SbomNode() => JsonNode.Parse("""
    {"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"hashes":[{"alg":"SHA-256","content":"HASH"}]}},"components":[{"name":"library"}]}
    """.Replace("HASH", Hash(Artifact)))!;
  public JsonNode ProvenanceNode() => JsonNode.Parse("""
    {"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"installer","digest":{"sha256":"HASH"}}],"predicate":{"buildDefinition":{"buildType":"https://build.example/type"},"runDetails":{"builder":{"id":"https://build.example/approved"}}}}
    """.Replace("HASH", Hash(Artifact)))!;
  public string Envelope(byte[]? sbom = null, byte[]? provenance = null, long sequence = 7, int root = 1, bool paused = false, string? url = null) =>
      Trust.Metadata(sequence, root, paused, Hash(Artifact), Hash(sbom ?? Sbom), Hash(provenance ?? Provenance), url, Artifact.Length);
  public VerifiedUpdateMetadata Metadata(byte[]? sbom = null, byte[]? provenance = null) =>
      new UpdateMetadataVerifier(Trust.Root()).Verify(Envelope(sbom, provenance), "sierra-business", "windows-x64", "stable", Trust.Now);
  public void Dispose() => Trust.Dispose();
}

public sealed class EvidenceTests
{
  [Fact]
  public void VerifiesExactArtifactAndSignerEndorsedApprovedBuilder()
  {
    using var f = new EvidenceFixture();
    var result = ReleaseEvidenceVerifier.Verify(f.Metadata(), f.Sbom, f.Provenance, [EvidenceFixture.Builder]);
    Assert.Equal(EvidenceFixture.Builder, result.BuilderId);
    Assert.Equal("https://build.example/type", result.BuildType);
    Assert.Equal(1, result.Components);
    foreach (var version in new[] { "1.4", "1.5", "1.6" })
    {
      var node = f.SbomNode(); node["specVersion"] = version;
      var bytes = Encoding.UTF8.GetBytes(node.ToJsonString());
      Assert.Equal(1, ReleaseEvidenceVerifier.Verify(f.Metadata(bytes), bytes, f.Provenance, [EvidenceFixture.Builder]).Components);
    }
  }

  [Fact]
  public void RejectsDigestTamperingAndUnapprovedBuilders()
  {
    using var f = new EvidenceFixture(); var metadata = f.Metadata();
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata, [1], f.Provenance, [EvidenceFixture.Builder]));
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata, f.Sbom, [1], [EvidenceFixture.Builder]));
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata, f.Sbom, f.Provenance, []));
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata, f.Sbom, f.Provenance, ["https://build.example/other"]));
    var changedSbom = f.SbomNode(); changedSbom["components"] = new JsonArray();
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata,
        Encoding.UTF8.GetBytes(changedSbom.ToJsonString()), f.Provenance, [EvidenceFixture.Builder]));
    var changedProvenance = f.ProvenanceNode(); changedProvenance["predicate"]!["buildDefinition"]!["buildType"] = "different-but-valid";
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(metadata, f.Sbom,
        Encoding.UTF8.GetBytes(changedProvenance.ToJsonString()), [EvidenceFixture.Builder]));
  }

  [Theory]
  [InlineData("format")]
  [InlineData("version")]
  [InlineData("artifact")]
  [InlineData("components")]
  [InlineData("statement")]
  [InlineData("predicate")]
  [InlineData("subject")]
  [InlineData("extra subject")]
  [InlineData("builder")]
  [InlineData("build type")]
  public void SignedEvidenceStillNeedsSemanticChecks(string error)
  {
    using var f = new EvidenceFixture(); var sbom = f.SbomNode(); var provenance = f.ProvenanceNode();
    switch (error)
    {
      case "format": sbom["bomFormat"] = "another-format"; break;
      case "version": sbom["specVersion"] = "9.0"; break;
      case "artifact": sbom["metadata"]!["component"]!["hashes"]![0]!["content"] = new string('0', 64); break;
      case "components": sbom["components"] = new JsonObject(); break;
      case "statement": provenance["_type"] = "https://in-toto.io/Statement/v0.1"; break;
      case "predicate": provenance["predicateType"] = "another-provenance"; break;
      case "subject": provenance["subject"]![0]!["digest"]!["sha256"] = new string('0', 64); break;
      case "extra subject": provenance["subject"]!.AsArray().Add(provenance["subject"]![0]!.DeepClone()); break;
      case "builder": provenance["predicate"]!["runDetails"]!["builder"]!["id"] = "https://build.example/unknown"; break;
      case "build type": provenance["predicate"]!["buildDefinition"]!["buildType"] = ""; break;
    }
    var s = Encoding.UTF8.GetBytes(sbom.ToJsonString()); var p = Encoding.UTF8.GetBytes(provenance.ToJsonString());
    Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(f.Metadata(s, p), s, p, [EvidenceFixture.Builder]));
  }

  [Fact]
  public void RejectsInvalidJsonDuplicateFieldsUtf8AndOversizedInputWithoutEchoingContent()
  {
    using var f = new EvidenceFixture();
    byte[][] bad = [Encoding.UTF8.GetBytes("{\"private-marker\":1,\"private-marker\":2}"), [255, 254],
      Encoding.UTF8.GetBytes("[]"), new byte[2 * 1024 * 1024 + 1]];
    foreach (var bytes in bad)
    {
      var error = Assert.Throws<UpdateVerificationException>(() => ReleaseEvidenceVerifier.Verify(f.Metadata(bytes), bytes, f.Provenance, [EvidenceFixture.Builder]));
      Assert.DoesNotContain("private-marker", error.Message);
    }
  }
}
