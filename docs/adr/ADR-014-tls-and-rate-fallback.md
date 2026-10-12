# ADR-014 — Verified database transport and continuous fallback counters

Status: Accepted. Trust boundaries: database transport and abuse controls.

The TLS guard must inspect the effective host, including the connection-string `host` override. Remote connections must use verified TLS: a misleading `ssl=true` cannot override an unsafe `sslmode`, and libpq compatibility is accepted only with `verify-full`. An explicitly configured CA continues to remove URL TLS overrides and require certificate verification. Existing explicit insecure-transport opt-in remains unchanged.

Rate limiting counts every request in bounded local memory, alongside the shared database counter. Failures and recovery therefore retain the local history. Healthy responses use the larger counter and longer TTL, conservatively handling differing window boundaries. This adds no database statements. Fallback remains per instance; it cannot preserve other instances' counts during a shared-store outage. Memory eviction, restart, and independent windows remain limits of this availability policy. Account lockout remains persistent in PostgreSQL.

Regression tests cover TLS downgrade flags, effective-host overrides, and rate-count continuity through failure and recovery. Existing database contracts cover persistent state and tenant isolation.
