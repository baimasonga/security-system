using System.Text.Json;
using Rokela.Updates;
using Xunit;

public sealed class CheckpointTests
{
  private static (string Root, string Envelope, DateTimeOffset Now) Fixture(string name = "valid metadata")
  {
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")));
    var c = doc.RootElement.GetProperty("cases").EnumerateArray().Single(c => c.GetProperty("name").GetString() == name);
    return (c.GetProperty("root").GetRawText(), c.GetProperty("envelope").GetRawText(),
        DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64()));
  }

  [Fact]
  public void RepeatedAuthenticatedPayloadAndAlternateSignatureEnvelopeAreStable()
  {
    var f = Fixture();
    var verifier = new UpdateCheckpointVerifier(f.Root);
    var first = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, null);
    Assert.Matches("^[0-9a-f]{64}$", first.Metadata.PayloadSha256);
    var second = verifier.Verify(Fixture("unknown signature does not veto valid threshold").Envelope,
        "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(10), first.Checkpoint);
    Assert.Equal(first.Metadata.PayloadSha256, second.Metadata.PayloadSha256);
    Assert.Equal(f.Now.ToUnixTimeSeconds() + 10, second.Checkpoint.LastSeen);
  }

  [Fact]
  public void RejectsRollbackAndAcceptsNewerReleaseWithoutMutatingPriorCheckpoint()
  {
    var f = Fixture(); var verifier = new UpdateCheckpointVerifier(f.Root);
    var first = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, null);
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(f.Envelope, "sierra-business", "windows-x64",
        "stable", f.Now, first.Checkpoint with { Sequence = 3 }));
    var next = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now,
        first.Checkpoint with { Sequence = 1 });
    Assert.Equal(2, next.Checkpoint.Sequence);
    Assert.Equal(2, first.Checkpoint.Sequence);
  }

  [Fact]
  public void AuthenticatedPauseAtSameSequenceIsEquivocation()
  {
    var f = Fixture(); var verifier = new UpdateCheckpointVerifier(f.Root);
    var first = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, null);
    var error = Assert.Throws<UpdateVerificationException>(() => verifier.Verify(Fixture("valid pause").Envelope,
        "sierra-business", "windows-x64", "stable", f.Now, first.Checkpoint));
    Assert.Contains("equivocation", error.Message);
  }

  [Fact]
  public void ClockToleranceNeverLowersWatermarkAndExpiredMetadataStillFails()
  {
    var f = Fixture(); var verifier = new UpdateCheckpointVerifier(f.Root);
    var first = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, null);
    var tolerated = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-60), first.Checkpoint);
    Assert.Equal(first.Checkpoint.LastSeen, tolerated.Checkpoint.LastSeen);
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(f.Envelope, "sierra-business", "windows-x64",
        "stable", f.Now.AddSeconds(-61), tolerated.Checkpoint));
    // Isolate checkpoint clock enforcement from the metadata's own future-issued check.
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(f.Envelope, "sierra-business", "windows-x64",
        "stable", f.Now, first.Checkpoint with { LastSeen = f.Now.ToUnixTimeSeconds() + 61 }));
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(f.Envelope, "sierra-business", "windows-x64",
        "stable", DateTimeOffset.FromUnixTimeSeconds(first.Metadata.Expires), first.Checkpoint));
  }

  [Fact]
  public void RejectsWrongRootTargetAndMalformedStateRatherThanResettingTrust()
  {
    var f = Fixture(); var verifier = new UpdateCheckpointVerifier(f.Root);
    var first = verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, null);
    UpdateCheckpoint[] bad = [
      first.Checkpoint with { RootSha256 = new string('0', 64) },
      first.Checkpoint with { Product = "another-product" },
      first.Checkpoint with { Platform = "linux-x64" },
      first.Checkpoint with { Channel = "beta" },
      first.Checkpoint with { Sequence = 0 },
      first.Checkpoint with { Sequence = long.MaxValue },
      first.Checkpoint with { LastSeen = -1 },
      first.Checkpoint with { LastSeen = long.MaxValue },
      first.Checkpoint with { PayloadSha256 = "invalid" }
    ];
    foreach (var state in bad)
      Assert.Throws<UpdateVerificationException>(() => verifier.Verify(f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, state));
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify("{}", "sierra-business", "windows-x64", "stable", f.Now, first.Checkpoint));
    Assert.Equal(2, first.Checkpoint.Sequence);
  }
}
