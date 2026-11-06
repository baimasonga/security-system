using System.Net;
using Rokela.Updates;
using Xunit;

internal sealed class StagingHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
  protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
  {
    var response = await send(request, token); response.RequestMessage ??= request; return response;
  }
}
internal sealed class StagingHarness : IDisposable
{
  public EvidenceFixture Fixture { get; } = new();
  public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "rokela-staging-test-" + Guid.NewGuid().ToString("N"));
  public UpdateTrustState State;
  public DateTimeOffset Now;
  public int Verifications;
  public List<string> Requests { get; } = [];
  public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? Send;
  public Action<int>? BeforeVerify;
  public StagingHarness()
  {
    Directory.CreateDirectory(DirectoryPath); Now = Fixture.Trust.Now;
    State = UpdateTrustVerifier.Initialize(Fixture.Trust.Root(), Fixture.Envelope(sequence: 6), "sierra-business", "windows-x64", "stable", Now).State;
  }
  public Task<VerifiedUpdateMetadata> Verify(string envelope, DateTimeOffset now, CancellationToken token)
  {
    token.ThrowIfCancellationRequested(); Verifications++; BeforeVerify?.Invoke(Verifications);
    var result = UpdateTrustVerifier.Verify(envelope, "sierra-business", "windows-x64", "stable", now, State);
    State = result.State; return Task.FromResult(result.Metadata);
  }
  public HttpResponseMessage Response(HttpRequestMessage request)
  {
    var path = request.RequestUri!.AbsolutePath;
    return new(HttpStatusCode.OK) { Content = new ByteArrayContent(path.EndsWith(".cdx.json") ? Fixture.Sbom :
        path.EndsWith(".intoto.json") ? Fixture.Provenance : Fixture.Artifact) };
  }
  public UpdateArtifactStager Stager(TimeSpan? timeout = null, long maximum = 1234, long installed = 6, string[]? builders = null,
      Func<string, DateTimeOffset, CancellationToken, Task<VerifiedUpdateMetadata>>? verify = null) => new(
      verify ?? Verify, DirectoryPath, builders ?? [EvidenceFixture.Builder], installed, maximum, new StagingHandler((request, token) =>
      {
        Requests.Add(request.RequestUri!.AbsolutePath);
        Assert.Equal("identity", request.Headers.AcceptEncoding.Single().Value);
        Assert.Null(request.Headers.Authorization); Assert.False(request.Headers.Contains("Cookie"));
        return Send?.Invoke(request, token) ?? Task.FromResult(Response(request));
      }), () => Now, timeout);
  public void Dispose() { Fixture.Dispose(); Directory.Delete(DirectoryPath, true); }
}

public sealed class StagingTests
{
  [Fact]
  public async Task StagesOnlyAfterEvidenceAndFinalCommitThenDisposesFile()
  {
    using var h = new StagingHarness(); string[] policy = [EvidenceFixture.Builder];
    using var stager = h.Stager(builders: policy); policy[0] = "changed-after-construction";
    var result = await stager.StageAsync(h.Fixture.Envelope());
    Assert.Equal(new[] { "/installer.exe.cdx.json", "/installer.exe.intoto.json", "/installer.exe" }, h.Requests);
    Assert.Equal(2, h.Verifications); Assert.Equal(7, h.State.Checkpoint.Sequence);
    Assert.Equal(h.Fixture.Artifact, File.ReadAllBytes(result.Path));
    Assert.Equal(EvidenceFixture.Builder, result.Evidence.BuilderId);
    Assert.StartsWith(h.DirectoryPath + Path.DirectorySeparatorChar, result.Path);
    if (!OperatingSystem.IsWindows()) Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
        File.GetUnixFileMode(Path.GetDirectoryName(result.Path)!));
    result.Dispose(); result.Dispose(); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Fact]
  public async Task EvidenceSuffixesKeepTheSignedOriginQueryAndEscapedPath()
  {
    using var h = new StagingHarness();
    h.Send = (request, _) =>
    {
      Assert.Equal("https://updates.example", request.RequestUri!.GetLeftPart(UriPartial.Authority));
      Assert.Equal("?public=fixture", request.RequestUri.Query);
      return Task.FromResult(h.Response(request));
    };
    using var stager = h.Stager();
    using var result = await stager.StageAsync(h.Fixture.Envelope(url: "https://updates.example/folder/install%20name.exe?public=fixture"));
    Assert.Equal(new[] { "/folder/install%20name.exe.cdx.json", "/folder/install%20name.exe.intoto.json", "/folder/install%20name.exe" }, h.Requests);
    Assert.Equal("artifact", Path.GetFileName(result.Path));
  }

  [Theory]
  [InlineData("paused")]
  [InlineData("installed")]
  [InlineData("size")]
  [InlineData("signature")]
  [InlineData("commit")]
  public async Task RefusesBeforeNetworkWhenReleaseOrCheckpointIsUnavailable(string mode)
  {
    using var h = new StagingHarness();
    if (mode == "commit") h.BeforeVerify = _ => throw new UpdateCheckpointStorageException();
    using var s = h.Stager(maximum: mode == "size" ? 1000 : 1234, installed: mode == "installed" ? 7 : 6);
    var error = await Record.ExceptionAsync(() => s.StageAsync(mode == "signature" ? "{}" : h.Fixture.Envelope(paused: mode == "paused")));
    Assert.NotNull(error); Assert.Empty(h.Requests); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Theory]
  [InlineData("redirect")]
  [InlineData("wrong final URL")]
  [InlineData("encoding")]
  [InlineData("status")]
  [InlineData("evidence digest")]
  [InlineData("large evidence")]
  public async Task BadEvidenceOrResponseNeverFetchesInstaller(string mode)
  {
    using var h = new StagingHarness();
    h.Send = (request, _) =>
    {
      var r = h.Response(request);
      switch (mode)
      {
        case "redirect": r.StatusCode = HttpStatusCode.Redirect; r.Headers.Location = new("https://other.example"); break;
        case "wrong final URL": r.RequestMessage = new(HttpMethod.Get, "https://other.example"); break;
        case "encoding": r.Content.Headers.ContentEncoding.Add("gzip"); break;
        case "status": r.StatusCode = HttpStatusCode.PartialContent; break;
        case "evidence digest": r.Content = new ByteArrayContent([1]); break;
        case "large evidence": r.Content = new ByteArrayContent(new byte[ReleaseEvidenceVerifier.MaximumBytes + 1]); break;
      }
      return Task.FromResult(r);
    };
    using var s = h.Stager();
    await Assert.ThrowsAsync<UpdateVerificationException>(() => s.StageAsync(h.Fixture.Envelope()));
    Assert.DoesNotContain("/installer.exe", h.Requests); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
    Assert.Equal(7, h.State.Checkpoint.Sequence); // A failed fetch must not forget the valid sequence already observed.
  }

  [Theory]
  [InlineData("hash")]
  [InlineData("short")]
  [InlineData("long")]
  [InlineData("declared length")]
  [InlineData("expired")]
  [InlineData("clock rollback")]
  [InlineData("newer release")]
  [InlineData("rotated authority")]
  [InlineData("final commit")]
  public async Task FailedArtifactOrFinalAuthorityCheckRemovesAllStaging(string mode)
  {
    using var h = new StagingHarness();
    if (mode == "final commit") h.BeforeVerify = n => { if (n == 2) throw new UpdateCheckpointStorageException(); };
    h.Send = (request, _) =>
    {
      var r = h.Response(request);
      if (request.RequestUri!.AbsolutePath == "/installer.exe")
      {
        if (mode == "hash") r.Content = new ByteArrayContent(new byte[1234]);
        if (mode == "short") { r.Content = new ByteArrayContent(new byte[1233]); r.Content.Headers.ContentLength = 1234; }
        if (mode == "long") { r.Content = new ByteArrayContent(new byte[1235]); r.Content.Headers.ContentLength = 1234; }
        if (mode == "declared length") r.Content.Headers.ContentLength = 1235;
        if (mode == "expired") h.Now = h.Now.AddSeconds(1800);
        if (mode == "clock rollback") h.Now = h.Now.AddSeconds(-61);
        if (mode == "newer release") h.State = UpdateTrustVerifier.Verify(h.Fixture.Envelope(sequence: 8), "sierra-business", "windows-x64", "stable", h.Now, h.State).State;
        if (mode == "rotated authority") h.State = UpdateTrustVerifier.Rotate(h.Fixture.Trust.Rotation(), "sierra-business", "windows-x64", "stable", h.Now, h.State);
      }
      return Task.FromResult(r);
    };
    using var s = h.Stager(); var error = await Record.ExceptionAsync(() => s.StageAsync(h.Fixture.Envelope()));
    Assert.True(error is UpdateVerificationException or UpdateCheckpointStorageException);
    Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Fact]
  public async Task DeadlineCoversStalledBodyAndCancellationLeavesNoFiles()
  {
    using var h = new StagingHarness();
    h.Send = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new StalledBody()) });
    using var s = h.Stager(TimeSpan.FromMilliseconds(80));
    var error = await Assert.ThrowsAsync<UpdateVerificationException>(() => s.StageAsync(h.Fixture.Envelope()).WaitAsync(TimeSpan.FromSeconds(3)));
    Assert.Contains("timeout", error.Message); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
    using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.StageAsync(h.Fixture.Envelope(), cancel.Token));
    Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Fact]
  public async Task CancelledTlsIoErrorsRetainTimeoutAndUserCancellationSemantics()
  {
    using var h = new StagingHarness();
    h.Send = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StreamContent(new CancelledIoBody()) });
    using var s = h.Stager(TimeSpan.FromMilliseconds(80));
    var error = await Assert.ThrowsAsync<UpdateVerificationException>(() => s.StageAsync(h.Fixture.Envelope()).WaitAsync(TimeSpan.FromSeconds(3)));
    Assert.Contains("timeout", error.Message);
    Assert.DoesNotContain("private", error.Message);
    using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(30));
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.StageAsync(h.Fixture.Envelope(), cancel.Token));
    Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Fact]
  public async Task CancellationDuringInstallerDownloadRemovesThePartialFile()
  {
    using var h = new StagingHarness(); using var cancel = new CancellationTokenSource();
    h.Send = (request, _) =>
    {
      if (request.RequestUri!.AbsolutePath == "/installer.exe") cancel.Cancel();
      return Task.FromResult(h.Response(request));
    };
    using var s = h.Stager();
    await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.StageAsync(h.Fixture.Envelope(), cancel.Token));
    Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [Fact]
  public async Task UnknownLengthEvidenceIsStoppedAtTheStreamingLimit()
  {
    using var h = new StagingHarness();
    h.Send = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
    { Content = new StreamContent(new UnknownLengthBody(new byte[ReleaseEvidenceVerifier.MaximumBytes + 1])) });
    using var s = h.Stager();
    var error = await Assert.ThrowsAsync<UpdateVerificationException>(() => s.StageAsync(h.Fixture.Envelope()));
    Assert.Contains("download size", error.Message);
    Assert.Single(h.Requests); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  [WindowsFact]
  public async Task NativeTrustStoreCommitsBeforeAndAfterStagingAndHoldsReadOnlyLease()
  {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
    using var h = new StagingHarness(); string statePath = Path.Combine(h.DirectoryPath, "trust.state");
    var trust = new WindowsUpdateTrustStore(statePath);
    await trust.InitializeAsync(h.Fixture.Trust.Root(), h.Fixture.Envelope(sequence: 6), "sierra-business", "windows-x64", "stable", h.Now);
    using var stager = h.Stager(verify: (envelope, now, ct) => trust.VerifyAndCommitAsync(envelope, "sierra-business", "windows-x64", "stable", now, ct));
    using var staged = await stager.StageAsync(h.Fixture.Envelope());
    Assert.Throws<IOException>(() => File.Open(staged.Path, FileMode.Open, FileAccess.Write, FileShare.Read).Dispose());
    var acl = new DirectoryInfo(Path.GetDirectoryName(staged.Path)!).GetAccessControl();
    Assert.True(acl.AreAccessRulesProtected);
    var rules = acl.GetAccessRules(true, true, typeof(System.Security.Principal.SecurityIdentifier))
        .Cast<System.Security.AccessControl.FileSystemAccessRule>().ToArray();
    Assert.Single(rules);
    using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
    Assert.Equal(identity.User, rules[0].IdentityReference);
    Assert.Equal(System.Security.AccessControl.AccessControlType.Allow, rules[0].AccessControlType);
    Assert.Equal(7, (await new WindowsUpdateTrustStore(statePath).VerifyAndCommitAsync(h.Fixture.Envelope(), "sierra-business", "windows-x64", "stable", h.Now)).Sequence);
  }

  [WindowsFact]
  public async Task NativeFinalCheckpointFailureDiscardsInstaller()
  {
    using var h = new StagingHarness(); string statePath = Path.Combine(h.DirectoryPath, "trust.state");
    var trust = new WindowsUpdateTrustStore(statePath);
    await trust.InitializeAsync(h.Fixture.Trust.Root(), h.Fixture.Envelope(sequence: 6), "sierra-business", "windows-x64", "stable", h.Now);
    FileStream? denyReplacement = null;
    h.Send = (request, _) =>
    {
      if (request.RequestUri!.AbsolutePath == "/installer.exe") denyReplacement = new(statePath, FileMode.Open, FileAccess.Read, FileShare.Read);
      return Task.FromResult(h.Response(request));
    };
    using var stager = h.Stager(verify: (envelope, now, ct) => trust.VerifyAndCommitAsync(envelope, "sierra-business", "windows-x64", "stable", now, ct));
    try
    {
      await Assert.ThrowsAsync<UpdateCheckpointStorageException>(() => stager.StageAsync(h.Fixture.Envelope()));
      Assert.Empty(Directory.GetDirectories(h.DirectoryPath));
    }
    finally { denyReplacement?.Dispose(); }
  }

  [Fact]
  public async Task SymbolicLinkStagingRootIsRefused()
  {
    using var h = new StagingHarness(); string link = h.DirectoryPath + "-link";
    // Creating symlinks requires privileges on Windows; the native ACL/file-share tests cover that platform separately.
    if (OperatingSystem.IsWindows()) return;
    Directory.CreateSymbolicLink(link, h.DirectoryPath);
    try
    {
      using var s = new UpdateArtifactStager(h.Verify, link, [EvidenceFixture.Builder], 6, 1234,
          new StagingHandler((request, _) => Task.FromResult(h.Response(request))), () => h.Now);
      await Assert.ThrowsAsync<UpdateVerificationException>(() => s.StageAsync(h.Fixture.Envelope()));
      Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
    }
    finally { Directory.Delete(link); }
  }

  private sealed class StalledBody : MemoryStream
  {
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    { await Task.Delay(Timeout.Infinite, token); return 0; }
  }
  private sealed class CancelledIoBody : MemoryStream
  {
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    {
      try { await Task.Delay(Timeout.Infinite, token); return 0; }
      catch (OperationCanceledException) { throw new IOException("private transport marker"); }
    }
  }
  private sealed class UnknownLengthBody(byte[] bytes) : MemoryStream(bytes)
  { public override bool CanSeek => false; }
}
