"""Check root/checkpoint invariants in a disposable copy; never mutate the checkout."""
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parent.parent
dotnet = os.environ.get("DOTNET_COMMAND", "dotnet")
with tempfile.TemporaryDirectory(prefix="rokela-trust-mutations-") as folder:
    copy = pathlib.Path(folder)
    shutil.copytree(root / "sdks/dotnet", copy / "sdks/dotnet", ignore=shutil.ignore_patterns("bin", "obj"))
    (copy / "docs/api").mkdir(parents=True)
    for name in ("update-metadata-vectors.json", "update-root-vectors.json"):
        shutil.copy2(root / "docs/api" / name, copy / "docs/api" / name)
    project = str(copy / "sdks/dotnet/Rokela.Updates.Tests")
    subprocess.run([dotnet, "restore", project, "--locked-mode"], check=True)
    command = [dotnet, "test", project, "--no-restore", "--configuration", "Release",
               "--filter", "FullyQualifiedName~TrustStateTests"]
    subprocess.run(command, check=True)
    source = copy / "sdks/dotnet/Rokela.Updates/UpdateTrustVerifier.cs"
    original = source.read_text()
    mutations = {
        "root binding": ("RootSha256 = hash,", "RootSha256 = state.Checkpoint.RootSha256,"),
        "release sequence preservation": ("RootSha256 = hash,", "RootSha256 = hash, Sequence = 1,"),
        "clock watermark preservation": (
            "Math.Max(now.ToUnixTimeSeconds(), state.Checkpoint.LastSeen)", "now.ToUnixTimeSeconds()"),
        "established-state validation": (
            "verifier.ValidateCheckpoint(product, platform, channel, now, state.Checkpoint);", ""),
    }
    for name, (before, after) in mutations.items():
        if original.count(before) != 1:
            raise RuntimeError("Mutation anchor must match exactly once: " + name)
        source.write_text(original.replace(before, after))
        run = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
        if run.returncode == 0 or not re.search(r"Failed:\s+[1-9]", run.stdout):
            print(run.stdout[-4000:])
            raise RuntimeError("Security assertion did not catch mutation: " + name)
        print("Caught negative control: " + name)
        source.write_text(original)
    subprocess.run(command, check=True)
