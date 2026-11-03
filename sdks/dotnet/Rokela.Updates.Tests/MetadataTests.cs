using System.Text.Json;
using Rokela.Updates;
using Xunit;

public sealed class MetadataTests
{
  public static IEnumerable<object[]> Vectors()
  {
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")));
    foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray()) yield return [c.GetProperty("name").GetString()!, c.GetRawText()];
  }
  [Theory]
  [MemberData(nameof(Vectors))]
  public void MatchesNodeMetadataDecisions(string name, string json)
  {
    Assert.NotEmpty(name);
    using var doc = JsonDocument.Parse(json);
    var c = doc.RootElement;
    VerifiedUpdateMetadata Run() => new UpdateMetadataVerifier(c.GetProperty("root").GetRawText()).Verify(
        c.GetProperty("envelope").GetRawText(), c.GetProperty("product").GetString()!, c.GetProperty("platform").GetString()!,
        c.GetProperty("channel").GetString()!, DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64()));
    if (c.GetProperty("accepted").GetBoolean())
    {
      var result = Run();
      Assert.Equal(2, result.Sequence);
      Assert.Equal("sierra-business", result.Product);
      Assert.Equal(1234, result.ArtifactSize);
      Assert.Equal(new string('a', 64), result.Sha256);
      Assert.Equal(name == "valid pause", result.Paused);
    }
    else Assert.Throws<UpdateVerificationException>(() => Run());
  }
  [Fact]
  public void RejectsDuplicateRootMembersAndOversizedUntrustedInputs()
  {
    Assert.Throws<UpdateVerificationException>(() => new UpdateMetadataVerifier("{\"schema\":1,\"schema\":1}"));
    Assert.Throws<UpdateVerificationException>(() => new UpdateMetadataVerifier(new string(' ', 65537)));
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")));
    var v = doc.RootElement.GetProperty("cases")[0];
    var verifier = new UpdateMetadataVerifier(v.GetProperty("root").GetRawText());
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(new string(' ', 524289), "sierra-business", "windows-x64", "stable", DateTimeOffset.FromUnixTimeSeconds(v.GetProperty("now").GetInt64())));
  }
}
