using System.Security.Cryptography;
using System.Text;

namespace Rokela.Updates;

/// <summary>One protected record: the current trusted root and its unchanged release history.</summary>
public sealed record UpdateTrustState(int Schema, string RootJson, UpdateCheckpoint Checkpoint);

/// <summary>
/// Pure immutable transitions. State is trusted only when loaded from integrity-protected storage;
/// callers must serialize and commit the complete result before acting on it. No installation authority.
/// </summary>
public static class UpdateTrustVerifier
{
  public static (VerifiedUpdateMetadata Metadata, UpdateTrustState State) Initialize(string pinnedRootJson,
      string envelope, string product, string platform, string channel, DateTimeOffset now)
  {
    var result = new UpdateCheckpointVerifier(pinnedRootJson).Verify(envelope, product, platform, channel, now, null);
    return (result.Metadata, new(1, pinnedRootJson, result.Checkpoint));
  }

  public static (VerifiedUpdateMetadata Metadata, UpdateTrustState State) Verify(string envelope,
      string product, string platform, string channel, DateTimeOffset now, UpdateTrustState state)
  {
    var verifier = Validate(state, product, platform, channel, now);
    var result = verifier.Verify(envelope, product, platform, channel, now, state.Checkpoint);
    return (result.Metadata, state with { Checkpoint = result.Checkpoint });
  }

  public static UpdateTrustState Rotate(string rotationEnvelope, string product, string platform, string channel,
      DateTimeOffset now, UpdateTrustState state)
  {
    Validate(state, product, platform, channel, now);
    string nextRoot = new UpdateMetadataVerifier(state.RootJson).VerifyRootRotation(rotationEnvelope, now);
    string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nextRoot))).ToLowerInvariant();
    return new(1, nextRoot, state.Checkpoint with
    {
      RootSha256 = hash,
      LastSeen = Math.Max(now.ToUnixTimeSeconds(), state.Checkpoint.LastSeen)
    });
  }

  private static UpdateCheckpointVerifier Validate(UpdateTrustState state, string product, string platform,
      string channel, DateTimeOffset now)
  {
    if (state is null || state.Schema != 1 || state.RootJson is null || state.Checkpoint is null)
      throw new UpdateVerificationException("trust state shape");
    var verifier = new UpdateCheckpointVerifier(state.RootJson);
    verifier.ValidateCheckpoint(product, platform, channel, now, state.Checkpoint);
    return verifier;
  }
}
