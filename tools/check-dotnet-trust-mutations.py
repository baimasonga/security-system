"""Check root/checkpoint invariants in a disposable copy; never mutate the checkout."""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
dotnet = os.environ.get("DOTNET_COMMAND", "dotnet")
staging = sys.argv[1:] == ["--staging"]
if sys.argv[1:] and not staging:
    raise SystemExit("Expected no arguments or --staging")

def annotate(message):
    text = re.sub(r"[A-Za-z0-9_+/=-]{40,}", "[redacted]", str(message)[:2000])
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print("::error title=Native mutation verification failure::" + text, flush=True)

def exception_report(kind, value, traceback):
    annotate(kind.__name__ + ": " + str(value))
    sys.__excepthook__(kind, value, traceback)

sys.excepthook = exception_report
with tempfile.TemporaryDirectory(prefix="rokela-trust-mutations-") as folder:
    copy = pathlib.Path(folder)
    shutil.copytree(root / "sdks/dotnet", copy / "sdks/dotnet", ignore=shutil.ignore_patterns("bin", "obj"))
    (copy / "docs/api").mkdir(parents=True)
    for name in ("update-metadata-vectors.json", "update-root-vectors.json"):
        shutil.copy2(root / "docs/api" / name, copy / "docs/api" / name)
    project = str(copy / "sdks/dotnet/Rokela.Updates.Tests")
    subprocess.run([dotnet, "restore", project, "--locked-mode"], check=True)
    command = [dotnet, "test", project, "--no-restore", "--configuration", "Release", "--logger", "trx;LogFileName=negative-controls.trx",
               "--filter", "FullyQualifiedName~EvidenceTests|FullyQualifiedName~StagingTests|FullyQualifiedName~StagingHttpsTests" if staging else "FullyQualifiedName~TrustStateTests"]

    def run_suite():
        return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", timeout=180)

    def require_clean_suite():
        run = run_suite()
        if run.returncode != 0:
            print(run.stdout[-4000:])
            subprocess.run([sys.executable, str(root / "tools/report-dotnet-test-failures.py"),
                            str(copy / "sdks/dotnet/Rokela.Updates.Tests/TestResults")], check=True)
            raise RuntimeError("Unmodified mutation baseline failed")
        print(run.stdout[-700:])

    require_clean_suite()
    mutations = {
        "root binding": ("RootSha256 = hash,", "RootSha256 = state.Checkpoint.RootSha256,"),
        "release sequence preservation": ("RootSha256 = hash,", "RootSha256 = hash, Sequence = 1,"),
        "clock watermark preservation": (
            "Math.Max(now.ToUnixTimeSeconds(), state.Checkpoint.LastSeen)", "now.ToUnixTimeSeconds()"),
        "established-state validation": (
            "verifier.ValidateCheckpoint(product, platform, channel, now, state.Checkpoint);", ""),
    }
    mutations = {name: ("UpdateTrustVerifier.cs", before, after) for name, (before, after) in mutations.items()}
    if staging:
        mutations = {
            "evidence digests": ("ReleaseEvidenceVerifier.cs",
                'if (Hash(sbom) != metadata.SbomSha256 || Hash(provenance) != metadata.ProvenanceSha256) Fail("evidence digest");', ""),
            "approved builder": ("ReleaseEvidenceVerifier.cs", '!trustedBuilders.Contains(builder, StringComparer.Ordinal)', "false"),
            "artifact integrity": ("UpdateArtifactStager.cs", 'if (actual != expected) throw new UpdateVerificationException("artifact integrity");', ""),
            "streaming byte limit": ("UpdateDownloadTransport.cs", 'if (size > maximum || (expected.HasValue && size > expected)) throw new UpdateVerificationException("download size");', ""),
            "final authority checkpoint": ("UpdateArtifactStager.cs", 'var final = await verify(envelope, clock(), cancellationToken);', 'var final = metadata;'),
            "failure cleanup": ("UpdateArtifactStager.cs", 'if (directory is not null) Remove(directory);', ""),
            "redirect refusal": ("UpdateDownloadTransport.cs", 'AllowAutoRedirect = false', 'AllowAutoRedirect = true'),
            "body deadline": ("UpdateDownloadTransport.cs", 'deadline.CancelAfter(timeout);', ""),
            "builder policy copy": ("UpdateArtifactStager.cs", 'builders = trustedBuilders.ToArray();', 'builders = trustedBuilders as string[] ?? trustedBuilders.ToArray();'),
        }
        if sys.platform == "win32":
            mutations["artifact read lease"] = ("UpdateArtifactStager.cs",
                'FileAccess.Read, FileShare.Read, 81920,', 'FileAccess.Read, FileShare.ReadWrite, 81920,')
            mutations["current-user-only ACL"] = ("UpdateArtifactStager.cs",
                'security.SetAccessRuleProtection(true, false);', 'security.SetAccessRuleProtection(false, false);')
    for name, (file, before, after) in mutations.items():
        source = copy / "sdks/dotnet/Rokela.Updates" / file
        original = source.read_text()
        if original.count(before) != 1:
            raise RuntimeError("Mutation anchor must match exactly once: " + name)
        source.write_text(original.replace(before, after))
        run = run_suite()
        if run.returncode == 0 or not re.search(r"Failed:\s+[1-9]", run.stdout):
            print(run.stdout[-4000:])
            annotate("Control: " + name + "; exit: " + str(run.returncode) + "; " + run.stdout[-1200:])
            raise RuntimeError("Security assertion did not catch mutation: " + name)
        print("Caught negative control: " + name)
        source.write_text(original)
    require_clean_suite()
