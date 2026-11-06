"""Windows-only negative-control checks; always restore the original source bytes."""
import pathlib
import re
import subprocess
import sys

if sys.platform != "win32":
    raise SystemExit("Native Windows is required for DPAPI mutation checks")

source = pathlib.Path("sdks/dotnet/Rokela.Updates/WindowsUpdateCheckpointStore.cs")
original = source.read_bytes()
text = original.decode("utf-8")
mutations = {
    "plaintext fallback": [
        ("ProtectedData.Protect(serialized, entropy, DataProtectionScope.CurrentUser)", "serialized.ToArray()"),
        ("ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser)", "encrypted.ToArray()"),
    ],
    "path binding": [
        ('SHA256.HashData(Encoding.UTF8.GetBytes("rokela/update-checkpoint/v1\\0" + path.ToUpperInvariant()))', "new byte[32]"),
    ],
    "transaction lock": [
        ("await using var gate = await AcquireAsync(cancellationToken);", "await using var gate = new MemoryStream();"),
    ],
    "replacement failure": [
        ("else File.Replace(temporary, path, null);", "else { try { File.Replace(temporary, path, null); } catch (IOException) { } }"),
    ],
}

try:
    for name, replacements in mutations.items():
        changed = text
        for before, after in replacements:
            if changed.count(before) != 1:
                raise RuntimeError("Mutation anchor must match exactly once: " + name)
            changed = changed.replace(before, after)
        source.write_text(changed, encoding="utf-8")
        run = subprocess.run(
            ["dotnet", "test", "sdks/dotnet/Rokela.Updates.Tests", "--no-restore",
             "--configuration", "Release", "--filter", "FullyQualifiedName~WindowsStoreTests|FullyQualifiedName~WindowsTrustStoreTests"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180,
        )
        if run.returncode == 0 or not re.search(r"Failed:\s+[1-9]", run.stdout):
            print(run.stdout[-4000:])
            raise RuntimeError("Security assertion did not catch mutation: " + name)
        print("Caught negative control: " + name)
finally:
    source.write_bytes(original)
