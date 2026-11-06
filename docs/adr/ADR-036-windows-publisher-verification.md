# ADR-036: Windows publisher verification for staged PE installers

Status: implemented publisher gate; native verification recorded with delivery.

The publisher gate accepts only a live `StagedUpdateArtifact`, not a caller-selected
path. Under its existing read lease, recheck the complete file length/SHA-256,
validate a bounded embedded PE signature layout, and call Windows WinVerifyTrust
with UI disabled and chain revocation checks (excluding the root). Always close
native trust state. Inspect the signer/certificate returned by that verified state,
not a separately extracted certificate. Require an independently configured SHA-256
fingerprint of the leaf certificate and a SHA-256/384/512 signature digest. Subject
names and SHA-1 store thumbprints never supply authority. Copy policy at construction.

PE support is deliberately conservative: one revision-2 PKCS#7 certificate table at
EOF, at most 4 MiB, canonical SignedData ContentInfo and zero alignment padding.
Reject unsigned/non-PE files, additional certificate entries, unhashed trailing data
and nonzero PKCS#7 padding. WinVerifyTrust still supplies cryptographic verification;
layout acceptance is not a signature verdict. MSI/scripts need separate adapters.

Verification shares a lock with staged-result disposal and passes the held handle to
WinVerifyTrust. No file is unlocked, replaced, executed or copied into an installation.
Return publisher evidence only. Release trust must be rechecked again before eventual
execution; publisher evidence is not a reusable installation grant. Native revocation
checks may use Windows network/cache policy and are synchronous; callers must keep
this off their UI thread. Do not introduce an offline-ignore-revocation switch.

The current Business Admin Inno installer overwrites files in place, prompts before
ending a running process, and keeps business data outside its install directory.
This does not establish atomic upgrade or schema-compatible rollback. Installation
journaling, explicit confirmation, interrupted-install reconciliation and product/data
recovery adapters remain separate implementation; do not call a successful signature
check a successful installation. No production keys or installed products change.

Native tests use disposable code-signing certificates in an isolated Windows CI
user profile, clean their certificate stores/private keys afterward, and never execute
the signed fixture. Cover approved/wrong pins, SHA-1 policy, untrusted-but-pinned,
unsigned/tampered PE, padding/overlay refusal and held/disposed leases. Portable
negative tests and isolated security mutations must accompany the native checks.
