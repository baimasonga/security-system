using System.Security.Cryptography;
using System.Text;

namespace Rokela.Updates;

/// <summary>Host-protected state for one exact pinned root and product/platform/channel.</summary>
public sealed record UpdateCheckpoint(string RootSha256, string Product, string Platform, string Channel,
    long Sequence, string PayloadSha256, long LastSeen);

/// <summary>
/// Pure checkpoint transition. The host must atomically persist the returned checkpoint before using metadata,
/// serialize concurrent transitions, and reject missing/corrupt existing state rather than treating it as first use.
/// This type provides no persistence, root rotation, artifact verification or installation authority.
/// </summary>
public sealed class UpdateCheckpointVerifier
{
  private readonly UpdateMetadataVerifier verifier;
  private readonly string rootHash;
  private const long SafeInteger = 9007199254740991;

  public UpdateCheckpointVerifier(string pinnedRootJson)
  {
    verifier = new(pinnedRootJson);
    rootHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pinnedRootJson))).ToLowerInvariant();
  }

  public (VerifiedUpdateMetadata Metadata, UpdateCheckpoint Checkpoint) Verify(string envelopeJson,
      string product, string platform, string channel, DateTimeOffset now, UpdateCheckpoint? previous)
  {
    ValidateCheckpoint(product, platform, channel, now, previous);
    long seconds = now.ToUnixTimeSeconds();
    var metadata = verifier.Verify(envelopeJson, product, platform, channel, now);
    if (previous is not null)
    {
      if (metadata.Sequence < previous.Sequence) throw new UpdateVerificationException("rollback");
      if (metadata.Sequence == previous.Sequence && metadata.PayloadSha256 != previous.PayloadSha256)
        throw new UpdateVerificationException("equivocation");
    }
    return (metadata, new(rootHash, product, platform, channel, metadata.Sequence, metadata.PayloadSha256,
        Math.Max(seconds, previous?.LastSeen ?? seconds)));
  }

  internal void ValidateCheckpoint(string product, string platform, string channel, DateTimeOffset now,
      UpdateCheckpoint? previous)
  {
    long seconds = now.ToUnixTimeSeconds();
    if (seconds is < 1 or > SafeInteger) throw new UpdateVerificationException("clock");
    if (previous is not null)
    {
      if (previous.RootSha256 != rootHash || previous.Product != product || previous.Platform != platform ||
          previous.Channel != channel || previous.Sequence is < 1 or > SafeInteger ||
          previous.LastSeen is < 1 or > SafeInteger || !Digest(previous.PayloadSha256))
        throw new UpdateVerificationException("checkpoint binding or shape");
      if (seconds < previous.LastSeen - 60)
        throw new UpdateVerificationException("clock rollback");
    }
  }

  private static bool Digest(string? value) => value is { Length: 64 } &&
      value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
