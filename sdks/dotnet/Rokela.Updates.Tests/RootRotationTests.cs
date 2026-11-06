using System.Text.Json;
using Rokela.Updates;
using Xunit;

public sealed class RootRotationTests
{
  public static IEnumerable<object[]> Vectors()
  {
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "root-vectors.json")));
    foreach (var c in doc.RootElement.GetProperty("cases").EnumerateArray())
      yield return [c.GetProperty("name").GetString()!, c.GetRawText()];
  }
  [Fact]
  public void RejectsMalformedOversizedAndExcessiveSignaturesWithoutLeakingInput()
  {
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "root-vectors.json")));
    var c = doc.RootElement.GetProperty("cases")[0];
    var verifier = new UpdateMetadataVerifier(c.GetProperty("root").GetRawText());
    var now = DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64());
    foreach (var input in new[] { new string(' ', 524289), "{\"signatures\":[],\"signatures\":[]}",
        JsonSerializer.Serialize(new { signatures = Enumerable.Repeat("private-input-marker", 33) }),
        JsonSerializer.Serialize(new { signatures = new[] { new string('a', 16385) } }) })
    {
      var error = Assert.Throws<UpdateVerificationException>(() => verifier.VerifyRootRotation(input, now));
      Assert.DoesNotContain("private-input-marker", error.Message);
    }
    Assert.Throws<UpdateVerificationException>(() => verifier.VerifyRootRotation(
        c.GetProperty("envelope").GetRawText(), DateTimeOffset.UnixEpoch));
  }
  [Theory]
  [MemberData(nameof(Vectors))]
  public void MatchesNodeRotationDecisions(string name, string json)
  {
    Assert.NotEmpty(name);
    using var doc = JsonDocument.Parse(json);
    var c = doc.RootElement;
    var verifier = new UpdateMetadataVerifier(c.GetProperty("root").GetRawText());
    string Run() => verifier.VerifyRootRotation(c.GetProperty("envelope").GetRawText(),
        DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64()));
    if (c.GetProperty("accepted").GetBoolean())
    {
      using var rotated = JsonDocument.Parse(Run());
      Assert.Equal(2, rotated.RootElement.GetProperty("version").GetInt64());
      Assert.True(System.Text.Json.Nodes.JsonNode.DeepEquals(
          System.Text.Json.Nodes.JsonNode.Parse(c.GetProperty("next").GetRawText()),
          System.Text.Json.Nodes.JsonNode.Parse(rotated.RootElement.GetRawText())));
      // Verification is stateless: it must not silently replace the trusted root.
      Assert.Equal(Run(), Run());
      Assert.Throws<UpdateVerificationException>(() => new UpdateMetadataVerifier(Run())
          .VerifyRootRotation(c.GetProperty("envelope").GetRawText(), DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64())));
    }
    else Assert.Throws<UpdateVerificationException>(() => Run());
  }
}
