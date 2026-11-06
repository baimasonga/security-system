using System.Text;
using System.Text.Json;
using NSec.Cryptography;
using Rokela.Updates;
using Xunit;

internal sealed class TrustFixture : IDisposable
{
  private readonly Key[] keys = Enumerable.Range(0, 6).Select(_ => new Key(SignatureAlgorithm.Ed25519)).ToArray();
  public DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
  private static string B64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
  public string Root(int version = 1) => JsonSerializer.Serialize(new
  {
    schema = 1, version, expires = Now.ToUnixTimeSeconds() + 3600,
    root = Role((version - 1) * 2), release = Role((version - 1) * 2 + 1),
    artifact_origins = new[] { "https://updates.example" }
  });
  private object Role(int index) => new
  {
    threshold = 1,
    keys = new[] { new { kid = "key-" + index, jwk = new { kty = "OKP", crv = "Ed25519", x = B64(keys[index].PublicKey.Export(KeyBlobFormat.RawPublicKey)) } } }
  };
  public string Rotation(int version = 2) => Envelope(Root(version), "trust-update-root+jws", (version - 2) * 2, (version - 1) * 2);
  public string Metadata(long sequence = 7, int rootVersion = 1, bool paused = false,
      string? artifactHash = null, string? sbomHash = null, string? provenanceHash = null, string? artifactUrl = null, long artifactSize = 1234) => Envelope(JsonSerializer.Serialize(new
  {
    schema = 1, product = "sierra-business", platform = "windows-x64", channel = "stable", sequence,
    version = "1.0.0", minimum_sequence = 1, issued_at = Now.ToUnixTimeSeconds(),
    expires = Now.ToUnixTimeSeconds() + 1800, paused,
    artifact = new { url = artifactUrl ?? "https://updates.example/installer.exe", size = artifactSize, sha256 = artifactHash ?? new string('a', 64),
      sbom_sha256 = sbomHash ?? new string('b', 64), provenance_sha256 = provenanceHash ?? new string('c', 64) }
  }), "trust-update-manifest+jws", (rootVersion - 1) * 2 + 1);
  private string Envelope(string payload, string purpose, params int[] indices) => JsonSerializer.Serialize(new
  {
    signatures = indices.Select(i =>
    {
      string signed = B64(JsonSerializer.SerializeToUtf8Bytes(new { alg = "EdDSA", typ = purpose, kid = "key-" + i })) + "." + B64(Encoding.UTF8.GetBytes(payload));
      return signed + "." + B64(SignatureAlgorithm.Ed25519.Sign(keys[i], Encoding.UTF8.GetBytes(signed)));
    }).ToArray()
  });
  public UpdateTrustState Initialize() => UpdateTrustVerifier.Initialize(Root(), Metadata(), "sierra-business", "windows-x64", "stable", Now).State;
  public void Dispose() { foreach (var key in keys) key.Dispose(); }
}

public sealed class TrustStateTests
{
  [Fact]
  public void RotationPreservesHistoryAndUsesReplacementReleaseKeysAcrossRestart()
  {
    using var f = new TrustFixture();
    var before = f.Initialize();
    var after = UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(20), before);
    Assert.NotEqual(before.RootJson, after.RootJson);
    Assert.NotEqual(before.Checkpoint.RootSha256, after.Checkpoint.RootSha256);
    Assert.Equal(before.Checkpoint.Sequence, after.Checkpoint.Sequence);
    Assert.Equal(before.Checkpoint.PayloadSha256, after.Checkpoint.PayloadSha256);
    Assert.Equal(f.Now.ToUnixTimeSeconds() + 20, after.Checkpoint.LastSeen);
    Assert.Equal(f.Now.ToUnixTimeSeconds(), before.Checkpoint.LastSeen);
    // Reconstruct state as a restarted host would; callers never repin the old root.
    var restarted = JsonSerializer.Deserialize<UpdateTrustState>(JsonSerializer.Serialize(after))!;
    var next = UpdateTrustVerifier.Verify(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(21), restarted);
    Assert.Equal(8, next.State.Checkpoint.Sequence);
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Verify(f.Metadata(9), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(21), restarted));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(21), restarted));
  }

  [Fact]
  public void RotationCannotResetSequenceEquivocationOrClockHistory()
  {
    using var f = new TrustFixture();
    var before = f.Initialize();
    var after = UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-60), before);
    Assert.Equal(before.Checkpoint.LastSeen, after.Checkpoint.LastSeen);
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Verify(f.Metadata(6, 2), "sierra-business", "windows-x64", "stable", f.Now, after));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Verify(f.Metadata(7, 2, true), "sierra-business", "windows-x64", "stable", f.Now, after));
    Assert.Equal(before.Checkpoint.PayloadSha256, UpdateTrustVerifier.Verify(f.Metadata(7, 2), "sierra-business", "windows-x64", "stable", f.Now, after).State.Checkpoint.PayloadSha256);
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-61), before));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(3), "sierra-business", "windows-x64", "stable", f.Now, before));
    var third = UpdateTrustVerifier.Rotate(f.Rotation(3), "sierra-business", "windows-x64", "stable", f.Now, after);
    Assert.Equal(7, third.Checkpoint.Sequence);
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Verify(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now, third));
  }

  [Fact]
  public void RejectsBadEstablishedStateAndWrongTargetBeforeRotation()
  {
    using var f = new TrustFixture(); var state = f.Initialize();
    UpdateTrustState[] bad = [state with { Schema = 0 }, state with { RootJson = f.Root(2) },
      state with { Checkpoint = state.Checkpoint with { Sequence = 0 } },
      state with { Checkpoint = state.Checkpoint with { PayloadSha256 = "invalid" } },
      state with { Checkpoint = state.Checkpoint with { LastSeen = f.Now.ToUnixTimeSeconds() + 61 } },
      state with { RootJson = null! }, state with { Checkpoint = null! }];
    foreach (var item in bad)
    {
      Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now, item));
      Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Verify(f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now, item));
    }
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "other", "windows-x64", "stable", f.Now, state));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "linux-x64", "stable", f.Now, state));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "beta", f.Now, state));
    Assert.Throws<UpdateVerificationException>(() => UpdateTrustVerifier.Rotate(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(3600), state));
  }
}
