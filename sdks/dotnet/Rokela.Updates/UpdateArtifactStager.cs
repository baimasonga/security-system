using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;

namespace Rokela.Updates;

/// <summary>A verified file, never installation authority. Dispose after use to close and remove it.</summary>
public sealed class StagedUpdateArtifact : IDisposable
{
  private FileStream? file;
  private readonly string directory;
  public string Path { get; }
  public VerifiedUpdateMetadata Metadata { get; }
  public VerifiedReleaseEvidence Evidence { get; }
  internal StagedUpdateArtifact(string directory, FileStream file, VerifiedUpdateMetadata metadata, VerifiedReleaseEvidence evidence)
  {
    this.directory = directory; this.file = file; Path = file.Name; Metadata = metadata; Evidence = evidence;
  }
  public void Dispose()
  {
    var lease = Interlocked.Exchange(ref file, null);
    if (lease is null) return;
    lease.Dispose();
    UpdateArtifactStager.Remove(directory);
  }
}

/// <summary>Bounded evidence-gated staging using the Windows protected trust store. Never executes software.</summary>
public sealed class UpdateArtifactStager : IDisposable
{
  private readonly Func<string, DateTimeOffset, CancellationToken, Task<VerifiedUpdateMetadata>> verify;
  private readonly string stagingRoot;
  private readonly string[] builders;
  private readonly long installedSequence, maximumBytes;
  private readonly TimeSpan timeout;
  private readonly Func<DateTimeOffset> clock;
  private readonly UpdateDownloadTransport transport;

  public UpdateArtifactStager(WindowsUpdateTrustStore trust, string product, string platform, string channel,
      string stagingDirectory, IReadOnlyCollection<string> trustedBuilders, long installedSequence,
      long maximumBytes = 256 * 1024 * 1024, TimeSpan? requestTimeout = null)
      : this(Bind(trust, product, platform, channel), stagingDirectory, trustedBuilders, installedSequence,
          maximumBytes, UpdateDownloadTransport.CreateHandler(), () => DateTimeOffset.UtcNow, requestTimeout) { }

  internal UpdateArtifactStager(Func<string, DateTimeOffset, CancellationToken, Task<VerifiedUpdateMetadata>> verify,
      string stagingDirectory, IReadOnlyCollection<string> trustedBuilders, long installedSequence, long maximumBytes,
      HttpMessageHandler handler, Func<DateTimeOffset> clock, TimeSpan? requestTimeout = null)
  {
    if (!System.IO.Path.IsPathFullyQualified(stagingDirectory)) throw new ArgumentException("Absolute staging path required");
    if (trustedBuilders.Count is < 1 or > 32 || trustedBuilders.Any(b => string.IsNullOrWhiteSpace(b) || b.Length > 2048))
      throw new ArgumentException("Approved builders required");
    if (installedSequence is < 0 or > 9007199254740991) throw new ArgumentOutOfRangeException(nameof(installedSequence));
    if (maximumBytes is < 1 or > 9007199254740991)
      throw new ArgumentOutOfRangeException(nameof(maximumBytes));
    timeout = requestTimeout ?? TimeSpan.FromSeconds(120);
    if (timeout <= TimeSpan.Zero || timeout > TimeSpan.FromMinutes(10)) throw new ArgumentOutOfRangeException(nameof(requestTimeout));
    this.verify = verify; stagingRoot = System.IO.Path.GetFullPath(stagingDirectory);
    builders = trustedBuilders.ToArray(); this.installedSequence = installedSequence; this.maximumBytes = maximumBytes;
    this.clock = clock; transport = new(handler);
  }

  public async Task<StagedUpdateArtifact> StageAsync(string envelope, CancellationToken cancellationToken = default)
  {
    string? directory = null; FileStream? file = null;
    try
    {
      cancellationToken.ThrowIfCancellationRequested();
      var metadata = await verify(envelope, clock(), cancellationToken);
      if (metadata.Paused || metadata.Sequence <= installedSequence) throw new UpdateVerificationException("release not stageable");
      if (metadata.ArtifactSize > maximumBytes) throw new UpdateVerificationException("artifact limit");
      var uri = new Uri(metadata.ArtifactUrl);
      var sbom = await EvidenceAsync(Sibling(uri, ".cdx.json"), cancellationToken);
      var provenance = await EvidenceAsync(Sibling(uri, ".intoto.json"), cancellationToken);
      var evidence = ReleaseEvidenceVerifier.Verify(metadata, sbom, provenance, builders);
      RejectLinks(stagingRoot);
      if (!Directory.Exists(stagingRoot)) throw new UpdateVerificationException("staging root unavailable");
      directory = System.IO.Path.Combine(stagingRoot, "rokela-update-" + Guid.NewGuid().ToString("N"));
      CreatePrivate(directory);
      string path = System.IO.Path.Combine(directory, "artifact");
      file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read, 81920,
          FileOptions.Asynchronous | FileOptions.WriteThrough);
      string hash = await transport.DownloadAsync(uri, file, maximumBytes, metadata.ArtifactSize, timeout, cancellationToken);
      CheckArtifactHash(hash, metadata.Sha256);
      await file.FlushAsync(cancellationToken); file.Flush(true);
      // A writable handle conflicts with ordinary read-sharing consumers on Windows.
      // Reopen read-only and rehash under that lease before returning any authority.
      file.Dispose();
      file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920,
          FileOptions.Asynchronous | FileOptions.SequentialScan);
      if (file.Length != metadata.ArtifactSize) throw new UpdateVerificationException("staged artifact size");
      CheckArtifactHash(Convert.ToHexString(await SHA256.HashDataAsync(file, cancellationToken)).ToLowerInvariant(), metadata.Sha256);
      cancellationToken.ThrowIfCancellationRequested();
      // Reload current trust/checkpoint. A concurrent rotation, newer release or expired metadata may now refuse it.
      var final = await verify(envelope, clock(), cancellationToken);
      cancellationToken.ThrowIfCancellationRequested();
      return new(directory, file, final, evidence);
    }
    catch (Exception error)
    {
      file?.Dispose();
      if (directory is not null) Remove(directory);
      if (error is OperationCanceledException)
      {
        if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException("Update staging cancelled", cancellationToken);
        throw new UpdateVerificationException("update timeout");
      }
      if (error is IOException or UnauthorizedAccessException or HttpRequestException or ObjectDisposedException or System.Security.SecurityException)
        throw new UpdateVerificationException("update staging unavailable");
      throw;
    }
  }

  private async Task<byte[]> EvidenceAsync(Uri uri, CancellationToken cancellationToken)
  {
    using var buffer = new MemoryStream();
    await transport.DownloadAsync(uri, buffer, ReleaseEvidenceVerifier.MaximumBytes, null,
        timeout < TimeSpan.FromSeconds(30) ? timeout : TimeSpan.FromSeconds(30), cancellationToken);
    return buffer.ToArray();
  }
  private static Uri Sibling(Uri uri, string suffix) => new UriBuilder(uri) { Path = uri.AbsolutePath + suffix }.Uri;
  private static void CheckArtifactHash(string actual, string expected)
  {
    if (actual != expected) throw new UpdateVerificationException("artifact integrity");
  }
  private static Func<string, DateTimeOffset, CancellationToken, Task<VerifiedUpdateMetadata>> Bind(
      WindowsUpdateTrustStore trust, string product, string platform, string channel)
  {
    ArgumentNullException.ThrowIfNull(trust);
    return (envelope, now, token) => trust.VerifyAndCommitAsync(envelope, product, platform, channel, now, token);
  }
  private static void CreatePrivate(string path)
  {
    if (OperatingSystem.IsWindows())
    {
      var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
      using var identity = WindowsIdentity.GetCurrent();
      security.AddAccessRule(new FileSystemAccessRule(identity.User!, FileSystemRights.FullControl,
          InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
      new DirectoryInfo(path).Create(security);
    }
    else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
  }
  private static void RejectLinks(string candidate)
  {
    for (string? current = candidate; current is not null; current = System.IO.Path.GetDirectoryName(current))
      if ((File.Exists(current) || Directory.Exists(current)) && (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
        throw new UpdateVerificationException("staging link");
  }
  internal static void Remove(string path)
  {
    if (!Directory.Exists(path)) return;
    try { Directory.Delete(path, true); }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
    { throw new UpdateVerificationException("staging cleanup unavailable"); }
  }
  public void Dispose() => transport.Dispose();
}
