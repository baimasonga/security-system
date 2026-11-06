using System.Net;
using System.Security.Cryptography;

namespace Rokela.Updates;

internal sealed class UpdateDownloadTransport : IDisposable
{
  private readonly HttpClient client;
  internal UpdateDownloadTransport(HttpMessageHandler handler)
      => client = new(handler, true) { Timeout = Timeout.InfiniteTimeSpan };

  internal static SocketsHttpHandler CreateHandler() => new()
  {
    AllowAutoRedirect = false, UseCookies = false,
    AutomaticDecompression = DecompressionMethods.None,
    ConnectTimeout = TimeSpan.FromSeconds(10), MaxResponseHeadersLength = 32,
    MaxConnectionsPerServer = 2, PooledConnectionLifetime = TimeSpan.FromMinutes(5)
  };

  internal async Task<string> DownloadAsync(Uri uri, Stream output, long maximum, long? expected,
      TimeSpan timeout, CancellationToken cancellationToken)
  {
    if (uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
      throw new UpdateVerificationException("download URL");
    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
    deadline.CancelAfter(timeout);
    try
    {
      using var request = new HttpRequestMessage(HttpMethod.Get, uri);
      request.Headers.AcceptEncoding.ParseAdd("identity");
      using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
      if (response.StatusCode != HttpStatusCode.OK || response.RequestMessage?.RequestUri != uri ||
          response.Content.Headers.ContentEncoding.Any(e => !e.Equals("identity", StringComparison.OrdinalIgnoreCase)))
        throw new UpdateVerificationException("download response");
      var declared = response.Content.Headers.ContentLength;
      if (declared is < 0 || declared > maximum || (expected.HasValue && declared.HasValue && declared != expected))
        throw new UpdateVerificationException("download length");
      await using var input = await response.Content.ReadAsStreamAsync(deadline.Token);
      using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
      byte[] buffer = new byte[81920]; long size = 0;
      while (true)
      {
        int read = await input.ReadAsync(buffer, deadline.Token);
        if (read == 0) break;
        size += read;
        if (size > maximum || (expected.HasValue && size > expected)) throw new UpdateVerificationException("download size");
        hash.AppendData(buffer, 0, read);
        await output.WriteAsync(buffer.AsMemory(0, read), deadline.Token);
      }
      if ((expected.HasValue && size != expected) || (declared.HasValue && size != declared))
        throw new UpdateVerificationException("download truncated");
      return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }
    catch (Exception error) when (deadline.IsCancellationRequested &&
        error is OperationCanceledException or IOException or HttpRequestException)
    {
      // TLS stacks can report a cancelled body read as IO instead of cancellation.
      throw new OperationCanceledException("Update download cancelled", deadline.Token);
    }
  }

  public void Dispose() => client.Dispose();
}
