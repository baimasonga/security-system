# ADR-035: Bounded native release-evidence staging

Status: implemented verification/staging; not an installed update client.

The .NET updater stages only a newer, unpaused signed release for a host-configured
product/platform/channel. An independently configured approved-builder list is
required. Persist the verified metadata checkpoint before network I/O; a failed
fetch must not forget an observed sequence. Fetch SBOM and provenance before the
artifact. Their signed SHA-256 digests must match the exact bytes, CycloneDX 1.4–1.6
must name this artifact, and an in-toto v1 / SLSA v1 statement must name exactly
this artifact and an approved builder. This authenticates signer-endorsed evidence;
it is not independent proof that a build actually ran as described.

Production transport uses normal system TLS verification, HTTPS only, no automatic
redirects, no cookies or credentials, identity content encoding, bounded response
headers, and cancellation/time budgets covering headers and streamed bodies. Each
evidence document is limited to 2 MiB; artifact streaming is bounded by the signed
size and a host maximum (default 256 MiB). Reject truncated, oversized, compressed,
non-200 or redirected responses. Never use an artifact filename from metadata.

Create a unique private staging directory beneath the host's trusted local staging
root. Write a new artifact file without executing it, verify exact length and SHA-256,
flush, then reverify the original envelope against the _current_ protected trust
state and current time. Expiry, rollback, changed release authority/origins,
equivocation, cancellation and a failed final checkpoint save discard the file.
No process lock is held during network I/O. Concurrent metadata checks/rotations
are allowed; final verification is the authority gate. All failure paths clean
partial staging. The caller owns disposal after successful staging.

The public Windows entry point requires the concrete DPAPI trust store. Tests use
an internal real-signature state adapter and transport seam, never a public
plaintext fallback. Verification results are not permission to execute an installer.
Native publisher verification, atomic installation, interruption recovery, product
integration and production hosting/signing remain separate slices. Trust directories
must be local and controlled by the host; DPAPI is not protection from the same
Windows user/admin rolling back or replacing all host data.
