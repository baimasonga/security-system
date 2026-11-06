using System.Buffers.Binary;
using System.Formats.Asn1;
using Rokela.Updates;
using Xunit;

public sealed class PeSignatureTests
{
  private static byte[] Layout()
  {
    var writer = new AsnWriter(AsnEncodingRules.DER);
    writer.PushSequence(); writer.WriteObjectIdentifier("1.2.840.113549.1.7.2");
    var context = new Asn1Tag(TagClass.ContextSpecific, 0, true);
    writer.PushSequence(context); writer.PushSequence(); writer.PopSequence(); writer.PopSequence(context); writer.PopSequence();
    byte[] pkcs = writer.Encode(); int entry = 8 + pkcs.Length, size = (entry + 7) / 8 * 8;
    var bytes = new byte[1024 + size]; bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
    BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(60), 128);
    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(128), 0x4550);
    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(148), 240);
    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(152), 0x20b);
    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(260), 16);
    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(296), 1024);
    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(300), (uint)size);
    BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1024), (uint)entry);
    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1028), 0x200);
    BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(1030), 2);
    pkcs.CopyTo(bytes, 1032); return bytes;
  }
  private static void Validate(byte[] bytes)
  {
    string path = Path.Combine(Path.GetTempPath(), "rokela-pe-"+Guid.NewGuid().ToString("N"));
    try
    {
      File.WriteAllBytes(path, bytes);
      using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
      EmbeddedPeSignature.Validate(file);
    }
    finally { File.Delete(path); }
  }
  [Fact]
  public void ParsesOnlyTheLayoutNotCryptographicAuthority() => Validate(Layout());
  [Theory]
  [InlineData("not PE")]
  [InlineData("huge offset")]
  [InlineData("truncated")]
  [InlineData("unsigned")]
  [InlineData("extra data")]
  [InlineData("padding")]
  [InlineData("wrong revision")]
  [InlineData("wrong type")]
  [InlineData("certificate size")]
  [InlineData("multiple entries")]
  public void RejectsUnhashedDataAndMalformedBoundaries(string mode)
  {
    byte[] bytes = Layout();
    switch (mode)
    {
      case "not PE": bytes[0] = 0; break;
      case "huge offset": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(60), uint.MaxValue); break;
      case "truncated": bytes = bytes[..150]; break;
      case "unsigned": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(300), 0); break;
      case "extra data": bytes = [..bytes, 1]; break;
      case "padding": bytes[^1] = 42; break;
      case "wrong revision": bytes[1029] = 1; break;
      case "wrong type": bytes[1030] = 1; break;
      case "certificate size": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(300), 4194305); break;
      case "multiple entries": BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(1024), 8); break;
    }
    Assert.Throws<UpdateVerificationException>(() => Validate(bytes));
  }
}
