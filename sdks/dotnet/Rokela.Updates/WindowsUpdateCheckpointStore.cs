using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Rokela.Updates;

public sealed class UpdateCheckpointStorageException() : Exception("Update checkpoint storage unavailable");

/// <summary>DPAPI CurrentUser checkpoints. Use a stable, dedicated trusted local path; never reset on failure.</summary>
public sealed class WindowsUpdateCheckpointStore
{
  private readonly string path;
  private readonly byte[] entropy;
  private readonly TimeSpan lockTimeout;
  private static readonly JsonSerializerOptions JsonOptions = new() { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };

  public WindowsUpdateCheckpointStore(string checkpointPath, TimeSpan? lockTimeout = null)
  {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows DPAPI required");
    if (!Path.IsPathFullyQualified(checkpointPath)) throw new ArgumentException("Absolute checkpoint path required");
    path = Path.GetFullPath(checkpointPath);
    this.lockTimeout = lockTimeout ?? TimeSpan.FromSeconds(10);
    if (this.lockTimeout <= TimeSpan.Zero || this.lockTimeout > TimeSpan.FromMinutes(1))
      throw new ArgumentOutOfRangeException(nameof(lockTimeout));
    entropy = SHA256.HashData(Encoding.UTF8.GetBytes("rokela/update-checkpoint/v1\0" + path.ToUpperInvariant()));
  }

  /// <summary>Only for explicitly authorized first use. Existing files are never overwritten.</summary>
  public Task<VerifiedUpdateMetadata> InitializeAsync(UpdateCheckpointVerifier verifier, string envelope,
      string product, string platform, string channel, DateTimeOffset now, CancellationToken cancellationToken = default) =>
      TransitionAsync(verifier, envelope, product, platform, channel, now, true, cancellationToken);

  public Task<VerifiedUpdateMetadata> VerifyAndCommitAsync(UpdateCheckpointVerifier verifier, string envelope,
      string product, string platform, string channel, DateTimeOffset now, CancellationToken cancellationToken = default) =>
      TransitionAsync(verifier, envelope, product, platform, channel, now, false, cancellationToken);

  private Task<VerifiedUpdateMetadata> TransitionAsync(UpdateCheckpointVerifier verifier, string envelope,
      string product, string platform, string channel, DateTimeOffset now, bool initialize, CancellationToken cancellationToken)
      => TransactAsync<UpdateCheckpoint, VerifiedUpdateMetadata>(previous =>
      {
        var result = verifier.Verify(envelope, product, platform, channel, now, previous);
        return (result.Checkpoint, result.Metadata);
      }, initialize, cancellationToken);

  // The trust store reuses exactly the same DPAPI, lock, cancellation and atomic-file transaction.
  internal async Task<TResult> TransactAsync<TState, TResult>(Func<TState?, (TState State, TResult Result)> transition,
      bool initialize, CancellationToken cancellationToken) where TState : class
  {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows DPAPI required");
    try
    {
      cancellationToken.ThrowIfCancellationRequested();
      var directory = Path.GetDirectoryName(path)!;
      RejectLinks(directory);
      Directory.CreateDirectory(directory);
      RejectLinks(directory);
      await using var gate = await AcquireAsync(cancellationToken);
      RejectLinks(path);
      TState? previous = null;
      if (initialize)
      {
        if (File.Exists(path) || Directory.Exists(path)) throw new UpdateCheckpointStorageException();
      }
      else
      {
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is < 1 or > 524288) throw new UpdateCheckpointStorageException();
        var encrypted = new byte[(int)file.Length];
        file.ReadExactly(encrypted);
        var clear = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser);
        try
        {
          previous = JsonSerializer.Deserialize<TState>(clear, JsonOptions) ?? throw new UpdateCheckpointStorageException();
        }
        finally { CryptographicOperations.ZeroMemory(clear); }
      }
      var result = transition(previous);
      cancellationToken.ThrowIfCancellationRequested();
      var serialized = JsonSerializer.SerializeToUtf8Bytes(result.State, JsonOptions);
      byte[] sealedState;
      try
      {
        if (serialized.Length > 450000) throw new UpdateCheckpointStorageException();
        sealedState = ProtectedData.Protect(serialized, entropy, DataProtectionScope.CurrentUser);
      }
      finally { CryptographicOperations.ZeroMemory(serialized); }
      string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
      try
      {
        using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            4096, FileOptions.WriteThrough))
        {
          output.Write(sealedState);
          output.Flush(true);
        }
        cancellationToken.ThrowIfCancellationRequested();
        RejectLinks(path);
        if (initialize) File.Move(temporary, path);
        else File.Replace(temporary, path, null);
      }
      finally { if (File.Exists(temporary)) File.Delete(temporary); }
      return result.Result;
    }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException or JsonException)
    {
      throw new UpdateCheckpointStorageException();
    }
  }

  private async Task<FileStream> AcquireAsync(CancellationToken cancellationToken)
  {
    var elapsed = Stopwatch.StartNew();
    while (true)
    {
      cancellationToken.ThrowIfCancellationRequested();
      RejectLinks(path + ".lock");
      try { return new FileStream(path + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
      catch (IOException) when (elapsed.Elapsed < lockTimeout)
      {
        await Task.Delay(TimeSpan.FromMilliseconds(25), cancellationToken);
      }
    }
  }

  private static void RejectLinks(string candidate)
  {
    for (string? current = candidate; current is not null; current = Path.GetDirectoryName(current))
      if ((File.Exists(current) || Directory.Exists(current)) &&
          (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
        throw new UpdateCheckpointStorageException();
  }
}
