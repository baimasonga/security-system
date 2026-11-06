using Rokela.Updates;
using Xunit;

public sealed class PublisherPolicyTests
{
  [Fact]
  public void PolicyIsPinnedIndependentOfSubjectAndCopiedFromCaller()
  {
    string[] pins = [new string('A', 64)]; var p = new PublisherPinPolicy(pins);
    pins[0] = new string('b', 64);
    Assert.Equal("SHA256", p.Verify(new string('a', 64), "2.16.840.1.101.3.4.2.1"));
    Assert.Equal("SHA384", p.Verify(new string('a', 64), "2.16.840.1.101.3.4.2.2"));
    Assert.Equal("SHA512", p.Verify(new string('a', 64), "2.16.840.1.101.3.4.2.3"));
    Assert.Throws<UpdateVerificationException>(() => p.Verify(new string('b', 64), "2.16.840.1.101.3.4.2.1"));
    Assert.Throws<UpdateVerificationException>(() => p.Verify(new string('a', 64), "1.3.14.3.2.26"));
    Assert.Throws<UpdateVerificationException>(() => p.Verify(new string('a', 64), "unknown"));
    Assert.Throws<ArgumentException>(() => new PublisherPinPolicy([]));
    Assert.Throws<ArgumentException>(() => new PublisherPinPolicy([new string('a', 40)]));
    Assert.Throws<ArgumentException>(() => new PublisherPinPolicy([" "+new string('a', 64)]));
  }

  [Fact]
  public void UnsupportedHostsNeverSubstituteHashOnlyPublisherChecks()
  {
    if (!OperatingSystem.IsWindows())
      Assert.Throws<PlatformNotSupportedException>(() => new WindowsPublisherVerifier([new string('a', 64)]).Verify(null!));
  }

  [Fact]
  public async Task DisposalWaitsUntilTheNativeHandleUseHasFinished()
  {
    string directory = Path.Combine(Path.GetTempPath(), "rokela-publisher-lease-"+Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(directory); string path = Path.Combine(directory,"artifact"); File.WriteAllBytes(path,[1]);
    using var entered = new ManualResetEventSlim(false); using var release = new ManualResetEventSlim(false);
    using var disposing = new ManualResetEventSlim(false);
    var metadata = new VerifiedUpdateMetadata("product","windows-x64","stable",1,"1.0.0",1,false,
        "https://updates.example/fixture",1,new string('a',64),new string('b',64),new string('c',64),long.MaxValue);
    using var artifact = new StagedUpdateArtifact(directory,File.OpenRead(path),metadata,new("builder","type",1));
    var verification = Task.Run(() => artifact.WithLockedHandle(handle =>
    {
      entered.Set(); Assert.True(release.Wait(TimeSpan.FromSeconds(10)));
      Assert.False(handle.IsClosed); return 42;
    }));
    Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
    var disposal = Task.Run(() => {disposing.Set();artifact.Dispose();});
    try
    {
      Assert.True(disposing.Wait(TimeSpan.FromSeconds(5)));
      await Task.Delay(200); Assert.False(disposal.IsCompleted);
    }
    finally
    {
      release.Set();
      try {await Task.WhenAll(verification,disposal);}
      finally {if(Directory.Exists(directory)) Directory.Delete(directory,true);}
    }
    Assert.Equal(42,await verification); Assert.False(File.Exists(path));
  }
}
