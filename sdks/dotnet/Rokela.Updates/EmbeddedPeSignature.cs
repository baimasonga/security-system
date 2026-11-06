using System.Buffers.Binary;
using System.Formats.Asn1;
using Microsoft.Win32.SafeHandles;

namespace Rokela.Updates;

/// <summary>Bounded layout checks; Windows must still authenticate the signature.</summary>
internal static class EmbeddedPeSignature
{
  internal static void Validate(SafeFileHandle handle)
  {
    try
    {
      long size = RandomAccess.GetLength(handle);
      var dos = Read(handle, 0, 64, size);
      if (dos[0] != 'M' || dos[1] != 'Z') Fail();
      int pe = BinaryPrimitives.ReadInt32LittleEndian(dos.AsSpan(60));
      if (pe is < 64 or > 1048576) Fail();
      var header = Read(handle, pe, 24, size);
      if (BinaryPrimitives.ReadUInt32LittleEndian(header) != 0x4550) Fail();
      int optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(20));
      if (optionalSize is < 136 or > 4096) Fail();
      var optional = Read(handle, pe + 24, optionalSize, size);
      int directories = BinaryPrimitives.ReadUInt16LittleEndian(optional) switch { 0x10b => 96, 0x20b => 112, _ => 0 };
      if (directories == 0 || optionalSize < directories + 40 || BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directories - 4)) < 5) Fail();
      long offset = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directories + 32));
      uint length = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directories + 36));
      if (length is < 8 or > 4194304 || offset < pe + 24 + optionalSize || offset % 8 != 0 || offset + length != size) Fail();
      var certificate = Read(handle, offset, (int)length, size);
      uint entryLength = BinaryPrimitives.ReadUInt32LittleEndian(certificate);
      if (entryLength < 8 || entryLength > length || ((long)entryLength + 7) / 8 * 8 != length ||
          BinaryPrimitives.ReadUInt16LittleEndian(certificate.AsSpan(4)) != 0x200 ||
          BinaryPrimitives.ReadUInt16LittleEndian(certificate.AsSpan(6)) != 2) Fail();
      var encoded = new AsnReader(certificate.AsMemory(8, (int)entryLength - 8), AsnEncodingRules.DER).ReadEncodedValue();
      var content = new AsnReader(encoded, AsnEncodingRules.DER).ReadSequence();
      if (content.ReadObjectIdentifier() != "1.2.840.113549.1.7.2" ||
          !content.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)) || !content.PeekTag().IsConstructed) Fail();
      content.ReadEncodedValue(); content.ThrowIfNotEmpty();
      var padding = certificate.AsSpan(8 + encoded.Length);
      if (padding.Length > 14 || padding.IndexOfAnyExcept((byte)0) >= 0) Fail();
    }
    catch (Exception e) when (e is AsnContentException or ArgumentException or OverflowException)
    { throw new UpdateVerificationException("embedded PE signature layout"); }
  }

  private static byte[] Read(SafeFileHandle handle, long offset, int count, long length)
  {
    if (offset < 0 || count < 0 || offset > length - count) Fail();
    var bytes = new byte[count]; int read = 0;
    while (read < count)
    {
      int n = RandomAccess.Read(handle, bytes.AsSpan(read), offset + read);
      if (n == 0) Fail();
      read += n;
    }
    return bytes;
  }
  private static void Fail() => throw new UpdateVerificationException("embedded PE signature layout");
}
