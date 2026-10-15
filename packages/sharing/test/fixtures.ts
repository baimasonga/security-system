import type {
  BlobRow,
  DocumentRow,
  JobRow,
  LinkRow,
  ShortLinkRow,
  SubmissionFileRow,
  SubmissionRow,
  TransferFileRow,
  TransferRow,
  UploadRequestRow,
  VersionRow,
} from '../src/index.ts';

export const T0 = new Date('2026-03-01T00:00:00Z');
let n = 0;
export const hex = (len = 64) =>
  Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('');
const id = (p: string) =>
  `${p}_${(++n).toString(16).padStart(6, '0')}${Math.random().toString(16).slice(2, 10)}`;

export const blob = (orgId: string, over: Partial<BlobRow> = {}): BlobRow => {
  const bid = id('blb');
  return {
    id: bid,
    orgId,
    objectKey: `o/${orgId}/${bid}`,
    ext: 'pdf',
    contentType: 'application/pdf',
    declaredSize: 100,
    size: null,
    sha256: null,
    status: 'uploading',
    rejectReason: null,
    multipartId: 'mp',
    partSize: 100,
    partCount: 1,
    uploadExpiresAt: new Date(+T0 + 3_600_000),
    targetType: 'transfer_file',
    targetId: 'x',
    note: null,
    createdBy: null,
    createdAt: T0,
    completedAt: null,
    scannedAt: null,
    deletedAt: null,
    ...(over.status === 'clean' ? { size: 100, sha256: 'a'.repeat(64) } : {}),
    ...over,
  };
};

export const document = (
  orgId: string,
  createdBy: string,
  over: Partial<DocumentRow> = {},
): DocumentRow => ({
  id: id('doc'),
  orgId,
  title: 'Contract',
  createdBy,
  draftBlobId: null,
  draftUpdatedAt: null,
  publishedVersionId: null,
  publishedAt: null,
  requireApproval: false,
  status: 'active',
  createdAt: T0,
  updatedAt: T0,
  ...over,
});

export const version = (
  orgId: string,
  documentId: string,
  blobId: string,
  createdBy: string,
  over: Partial<VersionRow> = {},
): VersionRow => ({
  id: id('ver'),
  orgId,
  documentId,
  number: 1,
  blobId,
  fileName: 'c.pdf',
  note: null,
  createdBy,
  createdAt: T0,
  publishedAt: null,
  replacementNote: null,
  ...over,
});

export const transfer = (
  orgId: string,
  createdBy: string,
  over: Partial<TransferRow> = {},
): TransferRow => ({
  id: id('trf'),
  orgId,
  createdBy,
  title: 'Files',
  message: null,
  kind: 'temporary',
  status: 'active',
  expiresAt: new Date(+T0 + 86_400_000),
  createdAt: T0,
  updatedAt: T0,
  ...over,
});

export const transferFile = (
  orgId: string,
  transferId: string,
  blobId: string,
  over: Partial<TransferFileRow> = {},
): TransferFileRow => ({
  id: id('tfl'),
  orgId,
  transferId,
  blobId,
  name: 'a.pdf',
  folderPath: '',
  ext: 'pdf',
  size: 100,
  status: 'current',
  revision: 1,
  replacedAt: null,
  replacementNote: null,
  createdAt: T0,
  updatedAt: T0,
  ...over,
});

export const link = (
  orgId: string,
  createdBy: string,
  targetId: string,
  over: Partial<LinkRow> = {},
): LinkRow => ({
  id: id('lnk'),
  orgId,
  salt: 'salt',
  tokenHash: hex(),
  createdBy,
  label: null,
  targetType: 'transfer',
  targetId,
  versionMode: null,
  versionId: null,
  permission: 'download',
  passwordHash: null,
  expiresAt: null,
  maxDownloads: null,
  downloadCount: 0,
  restriction: 'none',
  recipients: [],
  notifyOnAccess: false,
  status: 'active',
  statusReason: null,
  operatorHold: false,
  createdAt: T0,
  updatedAt: T0,
  ...over,
});

export const shortLink = (
  orgId: string,
  createdBy: string,
  over: Partial<ShortLinkRow> = {},
): ShortLinkRow => {
  const code = over.code ?? id('c').toLowerCase().replace(/_/g, '-');
  return {
    id: id('sln'),
    orgId,
    kind: 'public',
    domainId: null,
    code,
    salt: null,
    lookupKey: `p||${code}`,
    destinationType: 'external',
    destinationUrl: 'https://example.com/',
    targetId: null,
    status: 'active',
    statusReason: null,
    operatorHold: false,
    expiresAt: null,
    passwordHash: null,
    requireAuth: false,
    label: null,
    folder: '',
    tags: [],
    createdBy,
    createdAt: T0,
    updatedAt: T0,
    ...over,
  };
};

export const uploadRequest = (
  orgId: string,
  createdBy: string,
  over: Partial<UploadRequestRow> = {},
): UploadRequestRow => ({
  id: id('urq'),
  orgId,
  salt: 's',
  tokenHash: hex(),
  createdBy,
  title: 'Send documents',
  instructions: null,
  requirements: [{ key: 'id', label: 'ID', accept: ['pdf'], required: true, maxFiles: 1 }],
  deadline: new Date(+T0 + 86_400_000),
  maxFileBytes: 1000,
  maxTotalBytes: 5000,
  passwordHash: null,
  status: 'open',
  operatorHold: false,
  notify: false,
  deleteAfter: new Date(+T0 + 2 * 86_400_000),
  createdAt: T0,
  updatedAt: T0,
  ...over,
});

export const submission = (
  orgId: string,
  requestId: string,
  over: Partial<SubmissionRow> = {},
): SubmissionRow => ({
  id: id('sbm'),
  orgId,
  requestId,
  secretHash: hex(),
  submitterName: 'Ana',
  submitterEmail: null,
  status: 'open',
  createdAt: T0,
  submittedAt: null,
  ...over,
});

export const submissionFile = (
  orgId: string,
  requestId: string,
  submissionId: string,
  blobId: string,
  over: Partial<SubmissionFileRow> = {},
): SubmissionFileRow => ({
  id: id('sfl'),
  orgId,
  requestId,
  submissionId,
  blobId,
  requirementKey: 'id',
  name: 'id.pdf',
  ext: 'pdf',
  size: 100,
  status: 'current',
  createdAt: T0,
  ...over,
});

export const job = (orgId: string, over: Partial<JobRow> = {}): JobRow => ({
  id: id('job'),
  orgId,
  kind: 'scan',
  subjectId: 'blb_x',
  payload: {},
  runAfter: T0,
  attempts: 0,
  claim: null,
  lockedUntil: null,
  lastError: null,
  createdAt: T0,
  ...over,
});
