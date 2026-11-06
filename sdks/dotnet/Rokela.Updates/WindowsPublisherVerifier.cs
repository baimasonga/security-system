using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Rokela.Updates;

public sealed record VerifiedWindowsPublisher(string CertificateSha256, string Subject, string SignatureHash);

/// <summary>Windows signature trust and independent publisher pinning; never an installation grant.</summary>
public sealed class WindowsPublisherVerifier
{
  private readonly PublisherPinPolicy policy;
  public WindowsPublisherVerifier(IReadOnlyCollection<string> certificateSha256Pins) => policy = new(certificateSha256Pins);

  public VerifiedWindowsPublisher Verify(StagedUpdateArtifact artifact)
  {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows signature trust required");
    ArgumentNullException.ThrowIfNull(artifact);
    try
    {
      return artifact.WithLockedHandle(handle =>
      {
        if (artifact.Metadata.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
          throw new UpdateVerificationException("staged metadata expired");
        long size = RandomAccess.GetLength(handle);
        if (size != artifact.Metadata.ArtifactSize) throw new UpdateVerificationException("staged artifact size");
        using var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[81920]; long offset = 0;
        while (offset < size)
        {
          int read = RandomAccess.Read(handle, buffer.AsSpan(0, (int)Math.Min(buffer.Length, size - offset)), offset);
          if (read == 0) throw new UpdateVerificationException("staged artifact truncated");
          digest.AppendData(buffer, 0, read); offset += read;
        }
        if (Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant() != artifact.Metadata.Sha256)
          throw new UpdateVerificationException("staged artifact integrity");
        EmbeddedPeSignature.Validate(handle);
        var signer = NativeWindowsTrust.Verify(artifact.Path, handle.DangerousGetHandle());
        using var certificate = X509CertificateLoader.LoadCertificate(signer.Certificate);
        string fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToLowerInvariant();
        string algorithm = policy.Verify(fingerprint, signer.DigestOid);
        if (artifact.Metadata.Expires <= DateTimeOffset.UtcNow.ToUnixTimeSeconds())
          throw new UpdateVerificationException("staged metadata expired");
        return new VerifiedWindowsPublisher(fingerprint, certificate.GetNameInfo(X509NameType.SimpleName, false), algorithm);
      });
    }
    catch (Exception e) when (e is IOException or UnauthorizedAccessException or CryptographicException)
    { throw new UpdateVerificationException("publisher verification unavailable"); }
  }
}

internal sealed class PublisherPinPolicy
{
  private readonly HashSet<string> pins;
  internal PublisherPinPolicy(IReadOnlyCollection<string> values)
  {
    if (values.Count is < 1 or > 16 || values.Any(v => v is null || v.Length != 64 ||
        !v.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F')))
      throw new ArgumentException("SHA-256 publisher certificate fingerprints required");
    pins = values.Select(v => v.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
  }
  internal string Verify(string fingerprint, string digestOid)
  {
    if (!pins.Contains(fingerprint)) throw new UpdateVerificationException("publisher certificate pin");
    return digestOid switch
    {
      "2.16.840.1.101.3.4.2.1" => "SHA256",
      "2.16.840.1.101.3.4.2.2" => "SHA384",
      "2.16.840.1.101.3.4.2.3" => "SHA512",
      _ => throw new UpdateVerificationException("publisher signature digest")
    };
  }
}
