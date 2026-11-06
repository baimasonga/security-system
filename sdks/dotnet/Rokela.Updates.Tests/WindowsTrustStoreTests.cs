using System.Diagnostics;
using System.Text;
using Rokela.Updates;
using Xunit;

public sealed class WindowsTrustStoreTests : IDisposable
{
  private readonly string directory = Path.Combine(Path.GetTempPath(), "rokela-trust-" + Guid.NewGuid().ToString("N"));
  private string StatePath => Path.Combine(directory, "trust.state");
  public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }

  [Fact]
  public void NonWindowsNeverFallsBackToPlaintext()
  {
    if (!OperatingSystem.IsWindows()) Assert.Throws<PlatformNotSupportedException>(() => new WindowsUpdateTrustStore(StatePath));
  }

  [WindowsFact]
  public async Task RotationSurvivesRestartWithoutResettingReleaseHistory()
  {
    using var f = new TrustFixture(); var store = new WindowsUpdateTrustStore(StatePath);
    await store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    await store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(20));
    Assert.DoesNotContain("sierra-business", Encoding.UTF8.GetString(File.ReadAllBytes(StatePath)));
    Assert.DoesNotContain("artifact_origins", Encoding.UTF8.GetString(File.ReadAllBytes(StatePath)));
    var restarted = new WindowsUpdateTrustStore(StatePath);
    var saved = File.ReadAllBytes(StatePath);
    await Assert.ThrowsAsync<UpdateVerificationException>(() => restarted.VerifyAndCommitAsync(f.Metadata(6, 2), "sierra-business", "windows-x64", "stable", f.Now));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => restarted.VerifyAndCommitAsync(f.Metadata(7, 2, true), "sierra-business", "windows-x64", "stable", f.Now));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => restarted.VerifyAndCommitAsync(f.Metadata(8), "sierra-business", "windows-x64", "stable", f.Now));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => restarted.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => restarted.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-41)));
    Assert.Equal(saved, File.ReadAllBytes(StatePath));
    Assert.Equal(8, (await restarted.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(21))).Sequence);
  }

  [WindowsFact]
  public async Task FailedRotationCommitPreservesBothOldRootAndCheckpoint()
  {
    using var f = new TrustFixture(); var store = new WindowsUpdateTrustStore(StatePath);
    await store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    var saved = File.ReadAllBytes(StatePath);
    using (var denyReplacement = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.Read))
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(10)));
    Assert.Equal(saved, File.ReadAllBytes(StatePath));
    Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => store.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now));
    Assert.Equal(7, (await store.VerifyAndCommitAsync(f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now)).Sequence);
    await store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now);
    Assert.Equal(8, (await store.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now)).Sequence);
  }

  [WindowsFact]
  public async Task MissingCorruptCopiedAndLegacyStateCannotBecomeFirstUse()
  {
    using var f = new TrustFixture(); var store = new WindowsUpdateTrustStore(StatePath);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now));
    Assert.False(File.Exists(StatePath));
    await store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now));
    var good = File.ReadAllBytes(StatePath); string copiedPath = Path.Combine(directory, "copied.state");
    File.WriteAllBytes(copiedPath, good);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => new WindowsUpdateTrustStore(copiedPath).VerifyAndCommitAsync(f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now));
    foreach (byte[] bad in new[] { Array.Empty<byte>(), new byte[524289], good.Select(b => (byte)(b ^ 1)).ToArray() })
    {
      File.WriteAllBytes(StatePath, bad);
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now));
      Assert.Equal(bad, File.ReadAllBytes(StatePath));
    }
    File.Delete(StatePath);
    // Valid DPAPI legacy state still cannot be misread as rotating trust state.
    await new WindowsUpdateCheckpointStore(StatePath).InitializeAsync(new(f.Root()), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    var legacy = File.ReadAllBytes(StatePath);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now));
    Assert.Equal(legacy, File.ReadAllBytes(StatePath));
    File.Delete(StatePath);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now));
    Assert.False(File.Exists(StatePath));
  }

  [WindowsFact]
  public async Task ConcurrentRotationsCommitOnceAndNeverLowerClock()
  {
    using var f = new TrustFixture(); var store = new WindowsUpdateTrustStore(StatePath);
    await store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    using var start = new ManualResetEventSlim(false);
    string rotation = f.Rotation();
    var races = Enumerable.Range(0, 8).Select(_ => Task.Run(async () =>
    {
      start.Wait();
      try
      {
        await new WindowsUpdateTrustStore(StatePath).RotateRootAndCommitAsync(rotation, "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(30));
        return true;
      }
      catch (UpdateVerificationException) { return false; }
    })).ToArray();
    start.Set();
    Assert.Equal(1, (await Task.WhenAll(races)).Count(success => success));
    await Assert.ThrowsAsync<UpdateVerificationException>(() => store.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-31)));
    Assert.Equal(8, (await store.VerifyAndCommitAsync(f.Metadata(8, 2), "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(31))).Sequence);
  }

  [WindowsFact]
  public async Task RotationWaitsForSeparateProcessLockAndCancellationPreservesState()
  {
    using var f = new TrustFixture(); var store = new WindowsUpdateTrustStore(StatePath);
    await store.InitializeAsync(f.Root(), f.Metadata(), "sierra-business", "windows-x64", "stable", f.Now);
    var saved = File.ReadAllBytes(StatePath); string ready = Path.Combine(directory, "ready");
    static string Quote(string s) => "'" + s.Replace("'", "''") + "'";
    string script = "$f=[System.IO.File]::Open(" + Quote(StatePath + ".lock") +
        ",[System.IO.FileMode]::OpenOrCreate,[System.IO.FileAccess]::ReadWrite,[System.IO.FileShare]::None);" +
        "try{[System.IO.File]::WriteAllText(" + Quote(ready) + ",'ready');Start-Sleep -Seconds 30}finally{$f.Dispose()}";
    using var child = Process.Start(new ProcessStartInfo("powershell.exe")
    {
      UseShellExecute = false, CreateNoWindow = true,
      ArgumentList = { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }
    })!;
    try
    {
      var elapsed = Stopwatch.StartNew();
      while (!File.Exists(ready) && !child.HasExited && elapsed.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(25);
      Assert.True(File.Exists(ready), "Child did not acquire the trust-state lock");
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => new WindowsUpdateTrustStore(StatePath, TimeSpan.FromMilliseconds(100))
          .RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now));
      using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
      await Assert.ThrowsAnyAsync<OperationCanceledException>(() => store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now, cancel.Token));
      Assert.Equal(saved, File.ReadAllBytes(StatePath));
    }
    finally { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); }
    await store.RotateRootAndCommitAsync(f.Rotation(), "sierra-business", "windows-x64", "stable", f.Now);
  }
}
