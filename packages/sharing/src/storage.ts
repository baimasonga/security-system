// Private object storage port. Bytes move directly between the browser and storage through short-lived signed
// URLs on an ISOLATED origin; the API server authorizes each operation but never proxies file content.
// Adapters: local signed-URL store (development/tests, platform-api/src/integrations/object-store-local.ts) and
// S3-compatible storage such as Cloudflare R2 (platform-api/src/integrations/object-store-s3.ts).

export interface UploadedPart {
  partNumber: number;
  etag: string;
  size: number;
}

export interface SignedDownload {
  filename: string;
  contentType: string;
  disposition: 'inline' | 'attachment';
  expiresAt: Date;
}

export interface ObjectStore {
  readonly kind: string;
  /** Smallest part size the store accepts for every part but the last. */
  readonly minPartBytes: number;
  createMultipart(key: string, contentType: string): Promise<{ uploadId: string }>;
  /** URL for one `PUT` of exactly `bytes` bytes, valid until `expiresAt`. */
  signPart(
    key: string,
    uploadId: string,
    partNumber: number,
    bytes: number,
    expiresAt: Date,
  ): Promise<string>;
  /** Parts the store already holds: the basis of resuming an interrupted upload. */
  listParts(key: string, uploadId: string): Promise<UploadedPart[]>;
  completeMultipart(
    key: string,
    uploadId: string,
    parts: ReadonlyArray<{ partNumber: number; etag: string }>,
  ): Promise<{ size: number }>;
  /** Idempotent. */
  abortMultipart(key: string, uploadId: string): Promise<void>;
  head(key: string): Promise<{ size: number } | undefined>;
  /** Server-side read for quarantine checks (from the platform's own configured store only). */
  read(key: string): Promise<AsyncIterable<Uint8Array>>;
  signDownload(key: string, opts: SignedDownload): Promise<string>;
  /** Idempotent: deleting a missing object succeeds. */
  delete(key: string): Promise<void>;
}

/** Object keys never contain names or tenant-chosen text; they are opaque ids under a tenant prefix. */
export const objectKey = (orgId: string, blobId: string) => `o/${orgId}/${blobId}`;

// ---------------------------------------------------------------------------------------------------
// Quarantine checks
// ---------------------------------------------------------------------------------------------------

export interface ScanInput {
  /** Opens the stored object's bytes (may be called once per scanner in a chain). */
  open(): Promise<AsyncIterable<Uint8Array>>;
  ext: string;
}
export interface ScanVerdict {
  verdict: 'clean' | 'rejected';
  /** Machine-readable reason; never contains file content. */
  reason: string | null;
  sha256: string;
  size: number;
}
export interface FileScanner {
  readonly name: string;
  scan(input: ScanInput): Promise<ScanVerdict>;
}
