using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using NSec.Cryptography;

namespace Rokela.Updates;

public sealed class UpdateVerificationException(string reason) : Exception("Update metadata rejected: " + reason);

/// <summary>Authenticated metadata only. This result does not authorize installation or establish rollback safety.</summary>
public sealed record VerifiedUpdateMetadata(string Product, string Platform, string Channel, long Sequence,
    string Version, long MinimumSequence, bool Paused, string ArtifactUrl, long ArtifactSize,
    string Sha256, string SbomSha256, string ProvenanceSha256, long Expires);

/// <summary>
/// Stateless metadata inspection using an independently pinned public root. No network, storage, installation,
/// key rotation or rollback checkpoints. Hosts must not use this primitive as a complete update client.
/// </summary>
public sealed class UpdateMetadataVerifier
{
  private const long SafeInteger = 9007199254740991;
  private readonly long rootExpiry;
  private readonly int threshold;
  private readonly Dictionary<string, byte[]> releaseKeys;
  private readonly HashSet<string> origins;
  private static readonly JsonSerializerOptions JsonOptions = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

  public UpdateMetadataVerifier(string pinnedRootJson)
  {
    try
    {
      using var doc = Parse(pinnedRootJson, 65536);
      var root = doc.RootElement;
      Shape(root, "schema", "version", "expires", "root", "release", "artifact_origins");
      Require(Integer(root.GetProperty("schema")) == 1, "root schema");
      Integer(root.GetProperty("version"));
      rootExpiry = Integer(root.GetProperty("expires"));
      var rootKeys = Role(root.GetProperty("root"));
      var release = Role(root.GetProperty("release"));
      Require(!rootKeys.Keys.Keys.Intersect(release.Keys.Keys).Any() &&
          !rootKeys.Keys.Values.Select(Convert.ToHexString).Intersect(release.Keys.Values.Select(Convert.ToHexString)).Any(), "key separation");
      threshold = release.Threshold;
      releaseKeys = release.Keys;
      var allowed = root.GetProperty("artifact_origins");
      Require(allowed.ValueKind == JsonValueKind.Array && allowed.GetArrayLength() is >= 1 and <= 16, "origin policy");
      origins = new(StringComparer.Ordinal);
      foreach (var item in allowed.EnumerateArray())
      {
        var text = Text(item);
        var uri = Https(text);
        Require(uri.GetLeftPart(UriPartial.Authority) == text, "origin policy");
        origins.Add(text);
      }
    }
    catch (Exception e) when (Malformed(e)) { throw new UpdateVerificationException("malformed root"); }
  }

  public VerifiedUpdateMetadata Verify(string envelopeJson, string product, string platform, string channel, DateTimeOffset now)
  {
    try
    {
      Require(Label(product) && Label(platform) && Label(channel), "target");
      var seconds = now.ToUnixTimeSeconds();
      Require(rootExpiry > seconds, "expired root");
      using var envelope = Parse(envelopeJson, 524288);
      Shape(envelope.RootElement, "signatures");
      var signatures = envelope.RootElement.GetProperty("signatures");
      Require(signatures.ValueKind == JsonValueKind.Array && signatures.GetArrayLength() is >= 1 and <= 32, "signature envelope");
      var verified = new HashSet<string>(StringComparer.Ordinal);
      JsonElement? payload = null;
      string? canonical = null;
      foreach (var entry in signatures.EnumerateArray())
      {
        var token = Text(entry);
        Require(token.Length <= 16384, "signature envelope");
        JsonElement candidate;
        string kid;
        try
        {
          var parts = token.Split('.');
          Require(parts.Length == 3, "signature");
          using var header = JsonDocument.Parse(Decode(parts[0]));
          var h = header.RootElement;
          Unique(h);
          Require(Text(h.GetProperty("alg")) == "EdDSA" && Text(h.GetProperty("typ")) == "trust-update-manifest+jws", "signature purpose");
          kid = Text(h.GetProperty("kid"));
          if (!releaseKeys.TryGetValue(kid, out var bytes)) continue;
          var signature = Decode(parts[2]);
          if (signature.Length != 64) continue;
          var publicKey = PublicKey.Import(SignatureAlgorithm.Ed25519, bytes, KeyBlobFormat.RawPublicKey);
          if (!SignatureAlgorithm.Ed25519.Verify(publicKey, Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature)) continue;
          using var parsed = JsonDocument.Parse(Decode(parts[1]));
          Unique(parsed.RootElement);
          candidate = parsed.RootElement.Clone();
        }
        catch (Exception e) when (Malformed(e) || e is UpdateVerificationException) { continue; }
        var normalized = Canonical(candidate);
        Require(canonical is null || canonical == normalized, "conflicting signatures");
        canonical = normalized;
        payload = candidate;
        verified.Add(kid);
      }
      Require(verified.Count >= threshold && payload.HasValue, "signature threshold");
      var m = payload!.Value;
      Shape(m, "schema", "product", "platform", "channel", "sequence", "version", "minimum_sequence", "issued_at", "expires", "paused", "artifact");
      Require(Integer(m.GetProperty("schema")) == 1, "manifest schema");
      var p = Text(m.GetProperty("product")); var pl = Text(m.GetProperty("platform")); var c = Text(m.GetProperty("channel"));
      var version = Text(m.GetProperty("version"));
      Require(Label(p) && Label(pl) && Label(c) && Label(version), "manifest labels");
      Require(p == product && pl == platform && c == channel, "target binding");
      var sequence = Integer(m.GetProperty("sequence"));
      var minimum = Integer(m.GetProperty("minimum_sequence"), 0);
      Require(minimum <= sequence, "minimum sequence");
      var issued = Integer(m.GetProperty("issued_at")); var expires = Integer(m.GetProperty("expires"));
      Require(expires > seconds && issued <= seconds + 60 && expires > issued && expires - issued <= 604800, "freshness");
      var paused = m.GetProperty("paused");
      Require(paused.ValueKind is JsonValueKind.True or JsonValueKind.False, "paused flag");
      var a = m.GetProperty("artifact");
      Shape(a, "url", "size", "sha256", "sbom_sha256", "provenance_sha256");
      var url = Text(a.GetProperty("url"));
      Require(origins.Contains(Https(url).GetLeftPart(UriPartial.Authority)), "artifact origin");
      var size = Integer(a.GetProperty("size"));
      var hash = Digest(a.GetProperty("sha256")); var sbom = Digest(a.GetProperty("sbom_sha256")); var provenance = Digest(a.GetProperty("provenance_sha256"));
      return new(p, pl, c, sequence, version, minimum, paused.GetBoolean(), url, size, hash, sbom, provenance, expires);
    }
    catch (Exception e) when (Malformed(e)) { throw new UpdateVerificationException("malformed metadata"); }
  }

  private static (int Threshold, Dictionary<string, byte[]> Keys) Role(JsonElement role)
  {
    Shape(role, "threshold", "keys");
    var items = role.GetProperty("keys");
    Require(items.ValueKind == JsonValueKind.Array && items.GetArrayLength() is >= 1 and <= 16, "key policy");
    var count = Integer(role.GetProperty("threshold"));
    Require(count <= items.GetArrayLength(), "key threshold");
    var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
    var material = new HashSet<string>(StringComparer.Ordinal);
    foreach (var item in items.EnumerateArray())
    {
      Shape(item, "kid", "jwk");
      var kid = Text(item.GetProperty("kid")); Require(Label(kid), "key ID");
      var jwk = item.GetProperty("jwk"); Shape(jwk, "kty", "crv", "x");
      Require(Text(jwk.GetProperty("kty")) == "OKP" && Text(jwk.GetProperty("crv")) == "Ed25519", "public key");
      var bytes = Decode(Text(jwk.GetProperty("x")));
      Require(bytes.Length == 32 && keys.TryAdd(kid, bytes) && material.Add(Convert.ToHexString(bytes)), "duplicate or malformed key");
    }
    return ((int)count, keys);
  }
  private static JsonDocument Parse(string text, int limit)
  {
    Require(text is not null && text.Length <= limit, "size limit");
    var doc = JsonDocument.Parse(text!, new JsonDocumentOptions { MaxDepth = 16 });
    try { Unique(doc.RootElement); return doc; }
    catch { doc.Dispose(); throw; }
  }
  private static void Unique(JsonElement value)
  {
    if (value.ValueKind == JsonValueKind.Object)
    {
      var names = new HashSet<string>(StringComparer.Ordinal);
      foreach (var p in value.EnumerateObject()) { Require(names.Add(p.Name), "duplicate JSON member"); Unique(p.Value); }
    }
    else if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) Unique(item);
  }
  private static void Shape(JsonElement value, params string[] names)
  {
    Require(value.ValueKind == JsonValueKind.Object, "object required");
    var actual = value.EnumerateObject().Select(p => p.Name).ToArray();
    Require(actual.Length == names.Length && names.All(n => actual.Contains(n, StringComparer.Ordinal)), "object fields");
  }
  private static long Integer(JsonElement value, long minimum = 1)
  {
    Require(value.ValueKind == JsonValueKind.Number && value.TryGetDecimal(out var number) && number == decimal.Truncate(number) && number >= minimum && number <= SafeInteger, "integer");
    return (long)value.GetDecimal();
  }
  private static string Text(JsonElement value) { Require(value.ValueKind == JsonValueKind.String, "string required"); return value.GetString()!; }
  private static bool Label(string s) => Regex.IsMatch(s, "\\A[A-Za-z0-9][A-Za-z0-9._-]{0,79}\\z", RegexOptions.CultureInvariant);
  private static string Digest(JsonElement value) { var s = Text(value); Require(Regex.IsMatch(s, "\\A[a-f0-9]{64}\\z", RegexOptions.CultureInvariant), "digest"); return s; }
  private static Uri Https(string text)
  {
    Require(text.Length <= 2048 && !text.Any(char.IsControl) && Uri.TryCreate(text, UriKind.Absolute, out _), "artifact URL");
    var uri = new Uri(text);
    Require(uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Fragment.Length == 0, "artifact URL");
    return uri;
  }
  private static byte[] Decode(string text)
  {
    Require(text.Length > 0 && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'), "base64url");
    var bytes = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
    Require(Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') == text, "canonical base64url");
    return bytes;
  }
  private static string Canonical(JsonElement value) => value.ValueKind switch
  {
    JsonValueKind.Object => "{" + string.Join(',', value.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => JsonSerializer.Serialize(p.Name, JsonOptions) + ":" + Canonical(p.Value))) + "}",
    JsonValueKind.Array => "[" + string.Join(',', value.EnumerateArray().Select(Canonical)) + "]",
    JsonValueKind.String => JsonSerializer.Serialize(value.GetString(), JsonOptions),
    JsonValueKind.Number => JsonSerializer.Serialize(value.GetDouble(), JsonOptions),
    JsonValueKind.True => "true",
    JsonValueKind.False => "false",
    JsonValueKind.Null => "null",
    _ => throw new UpdateVerificationException("JSON value")
  };
  private static bool Malformed(Exception e) => e is JsonException or FormatException or InvalidOperationException or KeyNotFoundException or ArgumentException or OverflowException or CryptographicException;
  private static void Require(bool condition, string reason) { if (!condition) throw new UpdateVerificationException(reason); }
}
