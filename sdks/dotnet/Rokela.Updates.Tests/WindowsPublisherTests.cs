using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Rokela.Updates;
using Xunit;

[CollectionDefinition("Native publisher", DisableParallelization = true)]
public sealed class PublisherCollection : ICollectionFixture<PublisherFixture> { }

public sealed class PublisherFixture : IDisposable
{
  public string Root { get; } = Path.Combine(Path.GetTempPath(), "rokela-publisher-"+Guid.NewGuid().ToString("N"));
  public byte[] Trusted { get; } = [];
  public byte[] Untrusted { get; } = [];
  public string TrustedPin { get; } = "";
  public string UntrustedPin { get; } = "";
  private readonly List<string> thumbprints = [];
  internal static string Quote(string s) => "'"+s.Replace("'", "''")+"'";
  public PublisherFixture()
  {
    if (!OperatingSystem.IsWindows()) return;
    Directory.CreateDirectory(Root);
    string trusted = Path.Combine(Root, "trusted.exe"), untrusted = Path.Combine(Root, "untrusted.exe");
    File.Copy(typeof(WindowsPublisherVerifier).Assembly.Location, trusted);
    File.Copy(typeof(WindowsPublisherVerifier).Assembly.Location, untrusted);
    string script = """
      $ErrorActionPreference='Stop'; $created=New-Object 'System.Collections.Generic.List[string]'; $ok=$false
      function Sign-Fixture($path,$trust) {
        $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject ('CN=Rokela disposable CI publisher '+[Guid]::NewGuid().ToString('N')) -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable -HashAlgorithm SHA256 -NotAfter (Get-Date).AddDays(1)
        $created.Add($cert.Thumbprint)
        if($trust) {
          $public=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$cert.RawData)
          foreach($name in @('Root','TrustedPublisher')) {
            $store=New-Object System.Security.Cryptography.X509Certificates.X509Store($name,'CurrentUser')
            try {$store.Open('ReadWrite');$store.Add($public)} finally {$store.Close()}
          }
          $public.Dispose()
        }
        $result=Set-AuthenticodeSignature -FilePath $path -Certificate $cert -HashAlgorithm SHA256
        if($trust -and $result.Status -ne 'Valid') {throw ('Synthetic publisher signing was not accepted: '+$result.Status+'; '+$result.StatusMessage)}
        return @{thumbprint=$cert.Thumbprint;certificate=[Convert]::ToBase64String($cert.RawData)}
      }
      try {
      """ + "\n$a=Sign-Fixture " + Quote(trusted) + " $true\n$b=Sign-Fixture " + Quote(untrusted) + " $false\n" + """
        @{trusted=$a;untrusted=$b}|ConvertTo-Json -Compress; $ok=$true
      } finally {
        if(!$ok) {foreach($thumb in $created) {foreach($name in @('Root','TrustedPublisher')) {Remove-Item ('Cert:\CurrentUser\'+$name+'\'+$thumb) -ErrorAction SilentlyContinue};Remove-Item ('Cert:\CurrentUser\My\'+$thumb) -DeleteKey -ErrorAction SilentlyContinue}}
      }
      """;
    try
    {
      using var result = JsonDocument.Parse(Run(script));
      foreach (string name in new[] { "trusted", "untrusted" }) thumbprints.Add(result.RootElement.GetProperty(name).GetProperty("thumbprint").GetString()!);
      using var a = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(result.RootElement.GetProperty("trusted").GetProperty("certificate").GetString()!));
      using var b = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(result.RootElement.GetProperty("untrusted").GetProperty("certificate").GetString()!));
      TrustedPin = a.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
      UntrustedPin = b.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
      Trusted = File.ReadAllBytes(trusted); Untrusted = File.ReadAllBytes(untrusted);
    }
    catch { Dispose(); throw; }
  }
  internal StagedUpdateArtifact Stage(byte[] bytes, string? expectedHash = null)
  {
    string directory = Path.Combine(Root, Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
    string path = Path.Combine(directory, "artifact"); File.WriteAllBytes(path, bytes);
    var metadata = new VerifiedUpdateMetadata("sierra-business", "windows-x64", "stable", 7, "1.0.0", 1, false,
        "https://updates.example/fixture.exe", bytes.Length, expectedHash ?? EvidenceFixture.Hash(bytes), new string('b',64), new string('c',64),
        DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds());
    return new(directory, File.Open(path, FileMode.Open, FileAccess.Read, FileShare.Read), metadata,
        new(EvidenceFixture.Builder, "synthetic fixture", 1));
  }
  private static string Run(string script)
  {
    using var process = Process.Start(new ProcessStartInfo("powershell.exe")
    {
      UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true,
      ArgumentList = { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }
    })!;
    var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(60000)) { process.Kill(true); process.WaitForExit(); throw new InvalidOperationException("Synthetic signing timed out"); }
    if (process.ExitCode != 0) throw new InvalidOperationException("Synthetic signing failed: " + error.GetAwaiter().GetResult());
    return output.GetAwaiter().GetResult();
  }
  public void Dispose()
  {
    if (thumbprints.Count > 0)
    {
      string list = string.Join(',',thumbprints.Select(Quote));
      Run("""
        $ErrorActionPreference='Stop'
        foreach($thumb in @(@PINS@)) {
          foreach($name in @('Root','TrustedPublisher')) {Remove-Item ('Cert:\CurrentUser\'+$name+'\'+$thumb) -ErrorAction SilentlyContinue}
          Remove-Item ('Cert:\CurrentUser\My\'+$thumb) -DeleteKey -ErrorAction SilentlyContinue
          foreach($name in @('Root','TrustedPublisher','My')) {if(Test-Path ('Cert:\CurrentUser\'+$name+'\'+$thumb)) {throw 'Synthetic publisher certificate cleanup failed'}}
        }
        """.Replace("@PINS@",list));
      thumbprints.Clear();
    }
    if (Directory.Exists(Root)) Directory.Delete(Root,true);
  }
}

[Collection("Native publisher")]
public sealed class WindowsPublisherTests(PublisherFixture fixture)
{
  [WindowsFact]
  public async Task SignedMetadataProtectedStagingAndNativePublisherWorkTogether()
  {
    using var h = new StagingHarness(fixture.Trusted);
    var trust = new WindowsUpdateTrustStore(Path.Combine(h.DirectoryPath, "trust.state"));
    await trust.InitializeAsync(h.Fixture.Trust.Root(), h.Fixture.Envelope(sequence: 6), "sierra-business", "windows-x64", "stable", h.Now);
    using var stager = h.Stager(maximum: fixture.Trusted.Length,
        verify: (envelope, now, ct) => trust.VerifyAndCommitAsync(envelope, "sierra-business", "windows-x64", "stable", now, ct));
    using var artifact = await stager.StageAsync(h.Fixture.Envelope());
    Assert.Equal(fixture.TrustedPin, new WindowsPublisherVerifier([fixture.TrustedPin]).Verify(artifact).CertificateSha256);
    Assert.Equal(7, artifact.Metadata.Sequence);
  }
  [WindowsFact]
  public void AcceptsOnlyTheWindowsVerifiedPinnedSignerOnAnExtensionlessLease()
  {
    using var artifact = fixture.Stage(fixture.Trusted);
    var result = new WindowsPublisherVerifier([fixture.TrustedPin]).Verify(artifact);
    Assert.Equal(fixture.TrustedPin, result.CertificateSha256); Assert.Equal("SHA256", result.SignatureHash);
    Assert.Contains("Rokela disposable CI publisher", result.Subject);
    Assert.Equal("artifact", Path.GetFileName(artifact.Path));
    Assert.Throws<IOException>(() => File.Open(artifact.Path, FileMode.Open, FileAccess.Write, FileShare.Read).Dispose());
    Assert.Throws<UpdateVerificationException>(() => new WindowsPublisherVerifier([fixture.UntrustedPin]).Verify(artifact));
  }
  [WindowsFact]
  public void AMatchingPinCannotOverrideUntrustedWindowsSignatureState()
  {
    using var artifact = fixture.Stage(fixture.Untrusted);
    artifact.WithLockedHandle(h => { EmbeddedPeSignature.Validate(h); return true; });
    var error = Assert.Throws<UpdateVerificationException>(() => new WindowsPublisherVerifier([fixture.UntrustedPin]).Verify(artifact));
    Assert.Contains("Windows publisher trust", error.Message);
  }
  [WindowsFact]
  public void TamperedHashedCodeIsRejectedEvenWhenTheReleaseDigestMatchesIt()
  {
    byte[] tampered = fixture.Trusted.ToArray(); tampered[70] ^= 1;
    using var artifact = fixture.Stage(tampered);
    var error = Assert.Throws<UpdateVerificationException>(() => new WindowsPublisherVerifier([fixture.TrustedPin]).Verify(artifact));
    Assert.Contains("Windows publisher trust", error.Message);
  }
  [WindowsFact]
  public void MismatchedReleaseHashUnsignedPeAndUnhashedTrailingDataAreRejected()
  {
    var verifier = new WindowsPublisherVerifier([fixture.TrustedPin]);
    using var wrongHash = fixture.Stage(fixture.Trusted, new string('0',64));
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(wrongHash));
    using var unsigned = fixture.Stage(File.ReadAllBytes(typeof(WindowsPublisherVerifier).Assembly.Location));
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(unsigned));
    using var overlay = fixture.Stage([..fixture.Trusted, 1]);
    Assert.Throws<UpdateVerificationException>(() => verifier.Verify(overlay));
  }
  [WindowsFact]
  public void DisposedLeasesCannotBeUsedForPublisherChecks()
  {
    var artifact = fixture.Stage(fixture.Trusted); artifact.Dispose();
    Assert.Throws<UpdateVerificationException>(() => new WindowsPublisherVerifier([fixture.TrustedPin]).Verify(artifact));
  }
}
