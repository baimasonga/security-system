# Sharing retention and deletion policy (disclosed to customers)

This policy describes what Rokela PDF Pro sharing keeps and for how long. It is implemented by the maintenance pass
(`SharingService.runRetention`) and the deletion job worker; every step is retryable and idempotent.

| Data                                                               | Kept until                                                                                                                                   | Then                                                                                          |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Temporary transfer files                                           | The transfer's expiry (also after an earlier revocation)                                                                                     | Removed from object storage by the next retention pass (default every 60 s) and deletion jobs |
| Persistent transfer files                                          | The owner deletes the transfer or file                                                                                                       | Removed as above                                                                              |
| Replaced transfer files                                            | The replacement passes checks                                                                                                                | Earlier object removed                                                                        |
| Document drafts                                                    | Replaced by a newer draft, or document deleted                                                                                               | Removed unless an exported version still references the same object                           |
| Document versions                                                  | Document deleted                                                                                                                             | Removed                                                                                       |
| Upload-request files                                               | `deadline + retention days` (plan maximum), or immediately when the owner deletes the request; persistent plans may keep them until deletion | Removed                                                                                       |
| Unfinished uploads                                                 | 24 hours after they start                                                                                                                    | Multipart upload aborted, reservation released                                                |
| Rejected files (malware, wrong type, size mismatch, failed checks) | Immediately                                                                                                                                  | Removed                                                                                       |
| Link events / delivery receipts                                    | `SHARING_EVENT_RETENTION_DAYS` (default 180 days)                                                                                            | Deleted                                                                                       |
| Daily aggregates (counts only)                                     | 400 days                                                                                                                                     | Deleted                                                                                       |
| Notifications                                                      | 90 days                                                                                                                                      | Deleted                                                                                       |
| Password-attempt counters                                          | 1 day after the last failure                                                                                                                 | Deleted                                                                                       |
| Object metadata rows                                               | Kept as tombstones (no content) for audit                                                                                                    | —                                                                                             |
| Audit events                                                       | Per the platform audit policy (append-only)                                                                                                  | —                                                                                             |

An object is never deleted while a live draft, version, transfer file or submission file still references it.

## Backups

- **Object storage**: the sharing bucket must have object versioning **disabled** and no replication, so deleting
  an object removes it. Incomplete multipart uploads should additionally be aborted by a bucket lifecycle rule after
  2 days (defence in depth for crashes between creation and recording).
- **Database backups** contain metadata (titles, file names, recipients, receipts) but no file contents. They follow
  the database backup window (managed provider default, e.g. 7–35 days); deleted metadata disappears from backups when
  they age out. A restore must be followed by a retention pass, which re-deletes anything already due.
- A restored database may reference objects that were already deleted; those files show as unavailable, never as a
  different file.

Changing a retention period is an operator setting and requires updating this page.
