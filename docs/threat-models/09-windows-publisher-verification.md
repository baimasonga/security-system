# Windows staged publisher trust

The host supplies approved leaf-certificate SHA-256 fingerprints independently of
release metadata. The only public verification input is a live staged artifact.
Publisher subject/issuer text, SHA-1 store thumbprints and a Windows signature from
an unrelated publisher do not grant authority. A matching pin does not override an
untrusted, revoked, tampered or otherwise refused Windows signature.

The staged artifact retains a read-sharing file lease. Verification and disposal
share one lock; a native handle reference remains held throughout verification.
Recheck full length/hash and inspect only a bounded PE/PKCS#7 layout before calling
System32 WinVerifyTrust. UI is disabled. Native trust must return exactly zero;
inspect its verified signer state, require a SHA-2 signature digest and compare the
leaf certificate's exact DER SHA-256. Always close the native trust state before
releasing buffers or the file lease. Do not extract a second, potentially different
signer from the file after OS verification. Fixed refusal codes omit file paths.

The layout policy supports one revision-2 PKCS#7 PE certificate at EOF, zero padding
and bounded header/certificate reads. This removes common trailing/padding ambiguity;
it does not replace Windows cryptographic validation or prove every PE byte is
covered by Authenticode (its checksum/security directory and certificate region have
defined exclusions). Signed release hashes still bind the complete artifact bytes.

Native tests temporarily trust disposable CI code-signing certificates only in the
isolated Windows runner's CurrentUser stores, never execute their signed fixture,
and remove test certificates/private keys. Untrusted-but-pinned and tampered fixtures
must reach and fail OS signature trust. Portable tests and mutations cover exact
pins, strong hashes, overlay/padding bounds and concurrent disposal; native controls
also weaken the OS verdict and byte binding and must fail assertions.

This gate returns publisher evidence, not a reusable installation grant. Revalidate
release authority before future execution. OS revocation retrieval is synchronous
and may require a current network/cache result; no ignore-revocation fallback is
provided. Run the call away from UI work. The same user/admin can alter all host
state outside this threat boundary. Installation, process handoff, database-compatible
rollback and interrupted-update reconciliation need product-specific adapters.
