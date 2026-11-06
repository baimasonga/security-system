using System.Runtime.InteropServices;
using System.Text;

namespace Rokela.Updates;

internal sealed record NativePublisherSigner(byte[] Certificate, string DigestOid);

// Layouts follow Microsoft's WinTrust.h / WinCrypt.h (default Windows packing, native-width pointers).
internal static class NativeWindowsTrust
{
  internal static NativePublisherSigner Verify(string path, IntPtr heldFile)
  {
    Guid action = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    IntPtr name = Marshal.StringToCoTaskMemUni(path), file = IntPtr.Zero;
    var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2, RevocationChecks = 1,
      UnionChoice = 1, StateAction = 1, ProviderFlags = 0x80 | 0x2000 };
    try
    {
      file = Marshal.AllocHGlobal(Marshal.SizeOf<FileInfo>());
      Marshal.StructureToPtr(new FileInfo { Size = (uint)Marshal.SizeOf<FileInfo>(), Path = name, Handle = heldFile }, file, false);
      data.File = file;
      CheckTrust(WinVerifyTrust(new IntPtr(-1), ref action, ref data));
      IntPtr provider = WTHelperProvDataFromStateData(data.State);
      if (provider == IntPtr.Zero) Fail();
      IntPtr signerPointer = WTHelperGetProvSignerFromChain(provider, 0, false, 0);
      if (signerPointer == IntPtr.Zero) Fail();
      var signer = Marshal.PtrToStructure<ProviderSigner>(signerPointer);
      if (signer.Size < Marshal.SizeOf<ProviderSigner>() || signer.Certificates is < 1 or > 32 || signer.SignerInfo == IntPtr.Zero) Fail();
      CheckTrust(unchecked((int)signer.Error));
      IntPtr certPointer = WTHelperGetProvCertFromChain(signerPointer, 0);
      if (certPointer == IntPtr.Zero) Fail();
      var cert = Marshal.PtrToStructure<ProviderCertPrefix>(certPointer);
      if (cert.Size < Marshal.SizeOf<ProviderCertPrefix>() || cert.Context == IntPtr.Zero) Fail();
      var context = Marshal.PtrToStructure<CertContextPrefix>(cert.Context);
      if (context.Encoded == IntPtr.Zero || context.Length is < 1 or > 1048576) Fail();
      byte[] bytes = new byte[(int)context.Length]; Marshal.Copy(context.Encoded, bytes, 0, bytes.Length);
      var info = Marshal.PtrToStructure<SignerInfoPrefix>(signer.SignerInfo);
      return new(bytes, ReadOid(info.HashAlgorithm.Oid));
    }
    finally
    {
      if (data.State != IntPtr.Zero) { data.StateAction = 2; WinVerifyTrust(new IntPtr(-1), ref action, ref data); }
      if (file != IntPtr.Zero) Marshal.FreeHGlobal(file);
      Marshal.FreeCoTaskMem(name);
    }
  }

  private static void CheckTrust(int status)
  {
    if (status != 0) throw new UpdateVerificationException("Windows publisher trust " + unchecked((uint)status).ToString("x8"));
  }
  private static string ReadOid(IntPtr pointer)
  {
    if (pointer == IntPtr.Zero) Fail();
    byte[] bytes = new byte[128];
    for (int i = 0; i < bytes.Length; i++)
    {
      byte b = Marshal.ReadByte(pointer, i);
      if (b == 0) return Encoding.ASCII.GetString(bytes, 0, i);
      if (b > 127) Fail(); bytes[i] = b;
    }
    throw new UpdateVerificationException("Windows signature algorithm");
  }
  private static void Fail() => throw new UpdateVerificationException("Windows signature state");

  [StructLayout(LayoutKind.Sequential)]
  private struct TrustData
  {
    public uint Size; public IntPtr PolicyCallback, SipClient; public uint UiChoice, RevocationChecks, UnionChoice;
    public IntPtr File; public uint StateAction; public IntPtr State, UrlReference; public uint ProviderFlags, UiContext;
    public IntPtr SignatureSettings;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct FileInfo { public uint Size; public IntPtr Path, Handle, KnownSubject; }
  [StructLayout(LayoutKind.Sequential)]
  private struct ProviderSigner
  {
    public uint Size; public System.Runtime.InteropServices.ComTypes.FILETIME Time;
    public uint Certificates; public IntPtr Chain; public uint SignerType; public IntPtr SignerInfo;
    public uint Error, CounterSigners; public IntPtr Counters, ChainContext;
  }
  [StructLayout(LayoutKind.Sequential)]
  private struct ProviderCertPrefix { public uint Size; public IntPtr Context; }
  [StructLayout(LayoutKind.Sequential)]
  private struct CertContextPrefix { public uint Encoding; public IntPtr Encoded; public uint Length; }
  [StructLayout(LayoutKind.Sequential)]
  private struct Blob { public uint Length; public IntPtr Data; }
  [StructLayout(LayoutKind.Sequential)]
  private struct Algorithm { public IntPtr Oid; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)]
  private struct SignerInfoPrefix { public uint Version; public Blob Issuer, SerialNumber; public Algorithm HashAlgorithm; }

  [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
  [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
  [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provider, uint signer, [MarshalAs(UnmanagedType.Bool)] bool counterSigner, uint counter);
  [DllImport("wintrust.dll", ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint certificate);
}
