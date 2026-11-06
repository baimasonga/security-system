using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Rokela.Updates;
using Xunit;

public sealed class StagingHttpsTests
{
  [Theory]
  [InlineData(false)]
  [InlineData(true)]
  public async Task ActualTlsValidatesCertificatesAndStagesOnlyTrustedResponses(bool trusted)
  {
    using var h = new StagingHarness();
    await using var server = new HttpsFixture(path => path.EndsWith(".cdx.json") ? h.Fixture.Sbom : path.EndsWith(".intoto.json") ? h.Fixture.Provenance : h.Fixture.Artifact);
    using var stager = new UpdateArtifactStager(h.Verify, h.DirectoryPath, [EvidenceFixture.Builder], 6, 1234,
        server.Handler(trusted), () => h.Now);
    if (trusted)
    {
      StagedUpdateArtifact? staged = null;
      var error = await Record.ExceptionAsync(async () => staged = await stager.StageAsync(h.Fixture.Envelope()));
      Assert.True(error is null, "Client: " + error?.Message + "; synthetic TLS server: " + string.Join("; ", server.Failures));
      using var file = staged!;
      Assert.Equal(h.Fixture.Artifact, File.ReadAllBytes(file.Path)); Assert.Equal(3, server.Paths.Count);
    }
    else
    {
      await Assert.ThrowsAsync<UpdateVerificationException>(() => stager.StageAsync(h.Fixture.Envelope()));
      Assert.Empty(server.Paths); Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
    }
  }

  [Fact]
  public async Task ProductionHandlerNeverFollowsRedirects()
  {
    using var h = new StagingHarness();
    await using var server = new HttpsFixture(_ => [], redirect: true);
    using var stager = new UpdateArtifactStager(h.Verify, h.DirectoryPath, [EvidenceFixture.Builder], 6, 1234,
        server.Handler(true), () => h.Now);
    await Assert.ThrowsAsync<UpdateVerificationException>(() => stager.StageAsync(h.Fixture.Envelope()));
    Assert.Equal(new[] { "/installer.exe.cdx.json" }, server.Paths.ToArray());
    Assert.Equal(1, server.Connections);
  }

  [Fact]
  public async Task ActualTlsBodyStallHonorsTheRequestDeadline()
  {
    using var h = new StagingHarness();
    await using var server = new HttpsFixture(_ => [], stall: true);
    using var stager = new UpdateArtifactStager(h.Verify, h.DirectoryPath, [EvidenceFixture.Builder], 6, 1234,
        server.Handler(true), () => h.Now, TimeSpan.FromSeconds(2));
    var error = await Record.ExceptionAsync(() => stager.StageAsync(h.Fixture.Envelope()).WaitAsync(TimeSpan.FromSeconds(5)));
    Assert.True(error is UpdateVerificationException && error.Message.Contains("timeout", StringComparison.Ordinal),
        "Client: " + error?.Message + "; synthetic TLS server: " + string.Join("; ", server.Failures));
    Assert.Single(server.Paths);
    Assert.Empty(Directory.GetFileSystemEntries(h.DirectoryPath));
  }

  private sealed class HttpsFixture : IAsyncDisposable
  {
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly X509Certificate2 ca, leaf;
    private readonly Task accept;
    private readonly ConcurrentBag<Task> clients = [];
    private readonly Func<string, byte[]> content;
    private readonly bool redirect, stall;
    public ConcurrentQueue<string> Paths { get; } = [];
    public ConcurrentQueue<string> Failures { get; } = [];
    private int connections;
    public int Connections => connections;
    public HttpsFixture(Func<string, byte[]> content, bool redirect = false, bool stall = false)
    {
      this.content = content; this.redirect = redirect; this.stall = stall;
      using var caKey = RSA.Create(2048); using var key = RSA.Create(2048);
      var root = new CertificateRequest("CN=Rokela disposable test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
      root.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
      root.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
      ca = root.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
      var request = new CertificateRequest("CN=updates.example", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
      var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("updates.example"); request.CertificateExtensions.Add(san.Build());
      using var signed = request.Create(ca, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
      using var associated = signed.CopyWithPrivateKey(key);
      // Schannel cannot always use an ephemeral RSA key context. Import the disposable
      // test leaf with the normal key lifetime; never install its CA in system trust.
      byte[] pfx = associated.Export(X509ContentType.Pkcs12);
      try { leaf = X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.DefaultKeySet); }
      finally { CryptographicOperations.ZeroMemory(pfx); }
      listener.Start(); accept = AcceptAsync();
    }
    public SocketsHttpHandler Handler(bool trusted)
    {
      var handler = UpdateDownloadTransport.CreateHandler();
      // Test-only route: keep the signed updates.example hostname for TLS name checks.
      handler.UseProxy = false;
      handler.ConnectCallback = async (_, ct) =>
      {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        try { await socket.ConnectAsync((IPEndPoint)listener.LocalEndpoint, ct); return new NetworkStream(socket, true); }
        catch { socket.Dispose(); throw; }
      };
      if (trusted)
      {
        handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust,
          RevocationMode = X509RevocationMode.NoCheck };
        handler.SslOptions.CertificateChainPolicy.CustomTrustStore.Add(ca);
      }
      return handler;
    }
    private async Task AcceptAsync()
    {
      try
      {
        while (!stop.IsCancellationRequested)
        {
          var client = await listener.AcceptTcpClientAsync(stop.Token);
          Interlocked.Increment(ref connections); clients.Add(ServeAsync(client));
        }
      }
      catch (Exception e) when (e is OperationCanceledException or SocketException) { }
    }
    private async Task ServeAsync(TcpClient client)
    {
      using (client)
      await using (var ssl = new SslStream(client.GetStream()))
      {
        try
        {
          await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = leaf,
            ApplicationProtocols = [SslApplicationProtocol.Http11] }, stop.Token);
          var header = new StringBuilder(); byte[] b = new byte[1];
          while (!header.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
          {
            if (await ssl.ReadAsync(b, stop.Token) == 0) return;
            header.Append((char)b[0]); if (header.Length > 16384) throw new IOException();
          }
          string path = header.ToString().Split(' ')[1]; Paths.Enqueue(path);
          byte[] body = content(path);
          string response = redirect ? "HTTP/1.1 302 Found\r\nLocation: https://other.example/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" :
              $"HTTP/1.1 200 OK\r\nContent-Length: {(stall ? 100 : body.Length)}\r\nConnection: close\r\n\r\n";
          await ssl.WriteAsync(Encoding.ASCII.GetBytes(response), stop.Token);
          await ssl.FlushAsync(stop.Token);
          if (stall) await Task.Delay(Timeout.Infinite, stop.Token);
          else await ssl.WriteAsync(body, stop.Token);
        }
        catch (Exception e) when (e is IOException or AuthenticationException or OperationCanceledException)
        {
          if (!stop.IsCancellationRequested)
            Failures.Enqueue(e.GetType().Name + ": " + e.Message + "; " + e.InnerException?.GetType().Name + ": " + e.InnerException?.Message);
        }
      }
    }
    public async ValueTask DisposeAsync()
    {
      stop.Cancel(); listener.Stop(); await accept; await Task.WhenAll(clients); leaf.Dispose(); ca.Dispose(); stop.Dispose();
    }
  }
}
