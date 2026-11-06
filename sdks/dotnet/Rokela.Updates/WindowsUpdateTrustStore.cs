namespace Rokela.Updates;

/// <summary>
/// DPAPI CurrentUser root and checkpoint in one atomic file. Use a dedicated stable local path retained
/// across upgrades. Initialization is only for explicit first use, never recovery from a missing file.
/// Existing checkpoint-only files are not silently converted. No network or installation is performed.
/// </summary>
public sealed class WindowsUpdateTrustStore
{
  private readonly WindowsUpdateCheckpointStore storage;
  public WindowsUpdateTrustStore(string trustStatePath, TimeSpan? lockTimeout = null)
      => storage = new(trustStatePath, lockTimeout);

  public Task<VerifiedUpdateMetadata> InitializeAsync(string independentlyPinnedRootJson, string envelope,
      string product, string platform, string channel, DateTimeOffset now, CancellationToken cancellationToken = default)
      => storage.TransactAsync<UpdateTrustState, VerifiedUpdateMetadata>(_ =>
      {
        var result = UpdateTrustVerifier.Initialize(independentlyPinnedRootJson, envelope, product, platform, channel, now);
        return (result.State, result.Metadata);
      }, true, cancellationToken);

  public Task<VerifiedUpdateMetadata> VerifyAndCommitAsync(string envelope, string product, string platform,
      string channel, DateTimeOffset now, CancellationToken cancellationToken = default)
      => storage.TransactAsync<UpdateTrustState, VerifiedUpdateMetadata>(previous =>
      {
        var result = UpdateTrustVerifier.Verify(envelope, product, platform, channel, now, Required(previous));
        return (result.State, result.Metadata);
      }, false, cancellationToken);

  /// <summary>Commit the verified sequential root without clearing release/clock history. No root is repinned by the caller.</summary>
  public Task RotateRootAndCommitAsync(string envelope, string product, string platform, string channel,
      DateTimeOffset now, CancellationToken cancellationToken = default)
      => storage.TransactAsync<UpdateTrustState, bool>(previous =>
      {
        var result = UpdateTrustVerifier.Rotate(envelope, product, platform, channel, now, Required(previous));
        return (result, true);
      }, false, cancellationToken);

  private static UpdateTrustState Required(UpdateTrustState? state) => state ?? throw new UpdateCheckpointStorageException();
}
