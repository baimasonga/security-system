# Independent audit witness receiver

Implementation boundary: a separately administered AWS account, API Gateway HTTP
API, Lambda and S3 COMPLIANCE Object Lock. No deployment is authorized by this file.
The receiver has no Warrior database access. Operators must select account and
retention explicitly before deploying; retained versions cannot be deleted early.

The only public operation is authenticated `POST /anchors`. Validate the shared
version-1 digest plus strict shape, UTC timestamp, safe sequence integers, bounded
chain identifiers and SHA-256 hashes. Unknown fields are rejected. Authentication
precedes decoding; body limit is 1 MB and 5,000 chains. API Gateway/Lambda bound
request buffering; Lambda runs for at most 10 seconds and storage has an 8-second
deadline. No response includes request data, tokens or provider errors. Rate and
concurrency limits bound cost but cannot eliminate denial of service or billing abuse.

Canonical full manifests are addressed by SHA-256 (including observation time).
S3 conditional create prevents replacement; concurrent creates converge on the same
version. Retry after an ambiguous write reads that version. A successful receipt
requires HEAD confirmation of the version, matching metadata digest, COMPLIANCE mode
and unexpired retention. New writes must retain through the configured deadline.
The receipt identifies digest and version, not merely a mutable object name.
No HTTP download/delete endpoint exists. Independent readers retrieve exact versions.

Receiver IAM and bucket policy permit only conditional creation, reading metadata
needed for idempotency and retention inspection; no delete, retention editing or
bucket administration. Runtime policy cannot prevent a separate account administrator
from changing future policy or blocking access. COMPLIANCE protects existing versions
until expiry. A stolen sender token can submit false future evidence or consume quota;
it cannot erase earlier retained evidence. Authentication does not establish truthful
audit content. Independence, retention denial tests and real cloud recovery remain
deployment acceptance gates. Local fake-storage tests establish adapter behavior only.
