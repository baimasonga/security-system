# Independent audit witness

Implemented receiver and deployment template; **not deployed or cloud-accepted**.
Use an independently administered AWS account with separate recovery credentials.
No production database access or application secrets belong in this service.
Read [the setup guide](../../docs/deploy/audit-witness-setup.md) and
[threat model](../../docs/threat-models/audit-witness-receiver.md) before provisioning.

## Build and local checks

From the repository root, Node 22.18 or newer:

```sh
npm ci
npm ci --prefix infrastructure/audit-witness
npm --prefix infrastructure/audit-witness test
npm --prefix infrastructure/audit-witness run build
npm --prefix infrastructure/audit-witness run audit
npm run check
```

The SDK and bundler are pinned with a separate lockfile. The build produces
`dist/index.mjs`, bundling the shared audit contract and AWS SDK. The source Lambda
adapter tests substitute SDK calls and never contact AWS. Root tests cover receiver,
storage-port behavior, template permissions and synthetic audit tampering. These
tests cannot prove that an actual bucket denies deletion or has independent owners.

## Provision only after account and retention approval

1. Independently verify the selected AWS identity with `aws sts get-caller-identity`.
   Confirm it is the approved separate account and select the region explicitly.
2. Select a retention period (1–3,650 days; no template default). **COMPLIANCE
   retention cannot be shortened for existing versions, including by root.**
   The earlier proposal was 365 days; it is not an approved commitment.
3. Create a private Secrets Manager secret in that account/region with JSON field
   `token`, containing a separately generated 32–256-character printable secret.
   Enter it privately. Never use command-line plaintext, git, logs or chat.
4. Package `dist/index.mjs` as `index.mjs` at the ZIP root. Upload the ZIP to a private
   deployment-artifact bucket in the same account/region. Review the built artifact
   and record the source SHA and ZIP SHA-256 before deployment.
5. Create a CloudFormation change set from `template.yaml`, providing `CodeBucket`,
   `CodeKey`, `TokenSecretArn` and `RetentionDays`. Review IAM changes and resource
   costs. Execute only with approved account/retention. The deployment identity
   needs access to resolve the secret; the receiver does not get Secrets Manager
   access. Secret rotation requires refreshing the Lambda configuration/deployment.
6. Record outputs `WitnessUrl` and `EvidenceBucket`. Keep independent reader
   credentials separate from the receiver and the Warrior operator.

The template configures private, encrypted, versioned Object Lock storage; TLS-only
access; conditional writes; deletion denial; retained resources; a single POST route;
two concurrent Lambda invocations; and request throttling. Receiver IAM grants only
`PutObject`, `GetObject`, `GetObjectVersion` and `GetObjectRetention` on `anchors/*`.
It cannot list the bucket, edit retention or delete objects. Bucket default retention
is used for writes, then HEAD verifies the resulting exact version and deadline.
Request/access logs are intentionally disabled; use API Gateway/Lambda service metrics
and an independent external check for availability and errors. Set budgets/alerts in
the witness account before exposing the endpoint. Throttling does not eliminate costs.

## Protocol and independent retrieval

Only `POST /anchors`, `Content-Type: application/json`, with the dedicated bearer
token. Authenticate before decoding. Maximum decoded body: 1,000,000 bytes; maximum
5,000 chains; valid version-1 digest; strict fields and safe sequence numbers. API
Gateway buffers requests within its own service limits; Lambda runs at most 10 s and
all S3 calls share an 8 s abort deadline. Unknown routes/methods are refused. Fixed
errors never echo request data or provider messages.

Successful replies have `X-Witness-Receipt: v1:<digest>:<encoded-version>`. The digest
is SHA-256 of canonical full-manifest bytes, **not** the manifest's chain-head anchor.
Decode the final field as base64url to obtain the opaque S3 VersionId. Retrieve
`anchors/<digest>.json` with that exact version using independent read credentials.
Confirm the downloaded bytes' SHA-256 matches the receipt, inspect retention, then
use `tools/verify-anchor.ts` against the permitted database connection.

Receipts are bounded to Warrior's 256-character limit. Unexpected S3 version IDs
longer than 120 printable bytes are refused, not truncated. A new object's retention
deadline is checked to second precision; duplicate requests require an unexpired
locked version. Expired evidence is not renewed automatically. Conditional creation
and deletion denial preserve earlier object names and versions. Keep evidence and
the bucket when rolling back or deleting the stack.

## Required real-cloud acceptance

Before changing Warrior variables, use only synthetic manifests to verify invalid
token/body refusal, oversized request rejection, retries, concurrent writes, receiver
restart, ambiguous storage failures and retrieval of earlier versions after later
writes. Confirm `COMPLIANCE` mode and the selected deadline on every accepted version.
Using the receiver role, prove unconditional overwrite, deletion, retention editing,
bucket administration and arbitrary-prefix writes are denied. Read an exact version
with independent credentials and demonstrate that the existing audit verifier detects
an altered synthetic log. Do not modify production audit data for this test.

Then privately configure Warrior's endpoint/token and accept one real publication plus
independent retrieval/verification, following the setup guide. Keep the existing
disabled-anchoring warning until this acceptance succeeds. Neither a successful
Lambda build nor a local fake-store test establishes a live independent witness.
