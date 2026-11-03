using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Rokela.Updates;
using Xunit;

public sealed class WindowsFactAttribute : FactAttribute
{
  public WindowsFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Requires native Windows DPAPI"; }
}

public sealed class WindowsStoreTests : IDisposable
{
  private readonly string directory = Path.Combine(Path.GetTempPath(), "rokela-checkpoint-" + Guid.NewGuid().ToString("N"));
  private string StatePath => Path.Combine(directory, "update.state");
  private static (UpdateCheckpointVerifier Verifier, string Envelope, DateTimeOffset Now) Fixture()
  {
    using var doc = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "vectors.json")));
    var c = doc.RootElement.GetProperty("cases")[0];
    return (new(c.GetProperty("root").GetRawText()), c.GetProperty("envelope").GetRawText(),
        DateTimeOffset.FromUnixTimeSeconds(c.GetProperty("now").GetInt64()));
  }
  public void Dispose() { if (Directory.Exists(directory)) Directory.Delete(directory, true); }

  [Fact]
  public void UnsupportedHostsNeverFallBackToUnprotectedStorage()
  {
    if (!OperatingSystem.IsWindows()) Assert.Throws<PlatformNotSupportedException>(() => new WindowsUpdateCheckpointStore(StatePath));
  }

  [WindowsFact]
  public async Task PersistsProtectedStateAcrossInstancesAndRequiresExplicitFirstUse()
  {
    var f = Fixture(); var store = new WindowsUpdateCheckpointStore(StatePath);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
    var result = await store.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
    Assert.Equal(2, result.Sequence);
    Assert.DoesNotContain("sierra-business", Encoding.UTF8.GetString(File.ReadAllBytes(StatePath)));
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
    var restarted = new WindowsUpdateCheckpointStore(StatePath);
    Assert.Equal(2, (await restarted.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(1))).Sequence);
  }

  [WindowsFact]
  public async Task CorruptMissingOversizedAndCopiedStateNeverResetsHistory()
  {
    var f = Fixture(); var store = new WindowsUpdateCheckpointStore(StatePath);
    await store.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
    var good = File.ReadAllBytes(StatePath);
    string copiedPath = Path.Combine(directory, "copied.state");
    File.WriteAllBytes(copiedPath, good);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => new WindowsUpdateCheckpointStore(copiedPath).VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
    foreach (byte[] bad in new[] { Array.Empty<byte>(), new byte[65537], good.Select(b => (byte)(b ^ 1)).ToArray() })
    {
      File.WriteAllBytes(StatePath, bad);
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
      Assert.Equal(bad, File.ReadAllBytes(StatePath));
    }
    File.Delete(StatePath);
    await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
    Assert.False(File.Exists(StatePath));
  }

  [WindowsFact]
  public async Task ReplacementFailurePreservesPreviousCheckpointAndReturnsNoMetadata()
  {
    var f = Fixture(); var store = new WindowsUpdateCheckpointStore(StatePath);
    await store.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
    var before = File.ReadAllBytes(StatePath);
    using (var denyDelete = new FileStream(StatePath, FileMode.Open, FileAccess.Read, FileShare.Read))
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(10)));
    Assert.Equal(before, File.ReadAllBytes(StatePath));
    Assert.Empty(Directory.GetFiles(directory, "*.tmp"));
    await store.VerifyAndCommitAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
    var saved = File.ReadAllBytes(StatePath);
    await Assert.ThrowsAsync<UpdateVerificationException>(() => store.VerifyAndCommitAsync(f.Verifier, "{}", "sierra-business", "windows-x64", "stable", f.Now));
    Assert.Equal(saved, File.ReadAllBytes(StatePath));
  }

  [WindowsFact]
  public async Task IndependentInstancesSerializeAndKeepHighestClock()
  {
    var f = Fixture(); var first = new WindowsUpdateCheckpointStore(StatePath);
    await first.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
    using var start = new ManualResetEventSlim(false);
    var requests = Enumerable.Range(1, 20).Select(i => Task.Run(async () =>
    {
      start.Wait();
      await new WindowsUpdateCheckpointStore(StatePath).VerifyAndCommitAsync(f.Verifier, f.Envelope,
          "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(i));
    })).ToArray();
    start.Set();
    await Task.WhenAll(requests);
    await Assert.ThrowsAsync<UpdateVerificationException>(() => first.VerifyAndCommitAsync(f.Verifier, f.Envelope,
        "sierra-business", "windows-x64", "stable", f.Now.AddSeconds(-41)));
  }

  [WindowsFact]
  public async Task SeparateProcessLockIsRespectedAndWaitIsCancellable()
  {
    Directory.CreateDirectory(directory);
    var f = Fixture(); string ready = Path.Combine(directory, "ready");
    static string Quote(string text) => "'" + text.Replace("'", "''") + "'";
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
      var wait = Stopwatch.StartNew();
      while (!File.Exists(ready) && !child.HasExited && wait.Elapsed < TimeSpan.FromSeconds(10)) await Task.Delay(25);
      Assert.True(File.Exists(ready), "Child did not acquire the checkpoint lock");
      var store = new WindowsUpdateCheckpointStore(StatePath, TimeSpan.FromMilliseconds(100));
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => store.InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now));
      using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
      await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new WindowsUpdateCheckpointStore(StatePath)
          .InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now, cancel.Token));
      Assert.False(File.Exists(StatePath));
    }
    finally { if (!child.HasExited) child.Kill(true); await child.WaitForExitAsync(); }
    await new WindowsUpdateCheckpointStore(StatePath).InitializeAsync(f.Verifier, f.Envelope, "sierra-business", "windows-x64", "stable", f.Now);
  }
}
