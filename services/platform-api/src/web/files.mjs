// Files & links workspace: documents (compose/edit → private draft → immutable export → explicit publish), transfers
// with resumable file and folder uploads, share links, short links with QR codes, upload requests and notifications.
// Every action goes through the API, which authorizes it; this module only displays API-returned data.
import { composePdf, composerSource, fileKey, uploadFile } from './uploader.mjs';

let ui;
let tab = 'Overview';
const TABS = [
  'Overview',
  'Documents',
  'Transfers',
  'Share links',
  'Short links',
  'Upload requests',
  'Notifications',
];
const P = () => `${ui.orgPath()}/sharing`;
const enc = encodeURIComponent;
const fmtBytes = (n) => {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
};
const when = (d) => (d ? new Date(d).toLocaleString() : '—');
const DRAFT_SAVED =
  'Draft saved privately. It is never visible through share links until you export and publish it.';
const inDays = (days) => new Date(Date.now() + days * 86_400_000).toISOString();

function copyField(value, label) {
  const wrap = ui.node('div', undefined, 'copy-row');
  const input = ui.node('input');
  input.readOnly = true;
  input.value = value;
  input.setAttribute('aria-label', label);
  wrap.append(
    input,
    ui.button('Copy', async () => {
      input.select();
      try {
        await navigator.clipboard.writeText(value);
        ui.notice('Copied.');
      } catch {
        ui.notice('Select the text and copy it manually.');
      }
    }),
  );
  return wrap;
}

function progress() {
  const bar = ui.node('progress');
  bar.max = 100;
  bar.value = 0;
  const label = ui.node('span', '', 'progress-label');
  const box = ui.node('div', undefined, 'progress-row');
  box.append(bar, label);
  return {
    box,
    set: ({ sent, total, resumed }) => {
      bar.value = total ? Math.round((sent / total) * 100) : 100;
      label.textContent = `${fmtBytes(sent)} of ${fmtBytes(total)}${resumed ? ' · resumed' : ''}`;
    },
    done: (text) => (label.textContent = text),
  };
}

/** Owner upload with resume. `target` is the upload body without size/name. */
async function ownerUpload(file, target, bar, name = file.name) {
  return uploadFile({
    file,
    resumeKey: fileKey(`${ui.orgId()}:${JSON.stringify(target)}`, file),
    begin: () => ui.api(`${P()}/uploads`, 'POST', { ...target, name, size: file.size }),
    status: (id) => ui.api(`${P()}/uploads/${enc(id)}`),
    sign: (id, nums) => ui.api(`${P()}/uploads/${enc(id)}/parts`, 'POST', { part_numbers: nums }),
    complete: (id) => ui.api(`${P()}/uploads/${enc(id)}/complete`, 'POST', {}),
    onProgress: bar.set,
  });
}

async function download(type, id) {
  const r = await ui.api(`${P()}/files/download`, 'POST', { type, id });
  location.assign(r.url);
}

function tabs() {
  const bar = ui.node('div', undefined, 'tabs');
  bar.setAttribute('role', 'tablist');
  for (const t of TABS) {
    const b = ui.button(t, () => show(t));
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', String(t === tab));
    bar.append(b);
  }
  return bar;
}

async function show(next, ...args) {
  tab = next;
  ui.notice();
  try {
    ui.content.replaceChildren(...(await page(next, ...args)));
  } catch (e) {
    ui.errorMessage(e);
  }
}

export async function filesView(helpers) {
  ui = helpers;
  return page(tab);
}

async function page(name, ...args) {
  const head = [
    ui.title(
      'Files & links',
      'Share finished documents and files, collect uploads, and manage short links from one workspace.',
    ),
    tabs(),
  ];
  const body =
    name === 'Overview'
      ? await overview()
      : name === 'Documents'
        ? await documents(...args)
        : name === 'Transfers'
          ? await transfers(...args)
          : name === 'Share links'
            ? await links(...args)
            : name === 'Short links'
              ? await shortLinks(...args)
              : name === 'Upload requests'
                ? await requests(...args)
                : await notifications();
  return [...head, ...body];
}

// ---- overview -------------------------------------------------------------------------------------------
async function overview() {
  const o = await ui.api(`${P()}/overview`);
  const meter = (label, used, limit, fmt = fmtBytes) => {
    const m = ui.node('meter');
    m.min = 0;
    m.max = limit;
    m.value = Math.min(used, limit);
    const row = ui.node('div', undefined, 'meter-row');
    row.append(ui.node('span', label), m, ui.node('span', `${fmt(used)} of ${fmt(limit)}`));
    return row;
  };
  const yes = (b) => (b ? 'Included' : 'Not in plan');
  return [
    ui.panel(
      ui.node('h2', `Usage · ${o.period} (UTC)`),
      meter('Storage', o.usage.storage_bytes, o.limits.storage_bytes),
      meter('Bandwidth this month', o.usage.bandwidth_bytes, o.limits.bandwidth_bytes_per_month),
      meter('Processing this month', o.usage.processing_bytes, o.limits.processing_bytes_per_month),
      meter('API changes this month', o.usage.api_requests, o.limits.api_requests_per_month, (n) =>
        String(n),
      ),
      ui.node(
        'p',
        'Bandwidth counts the size of each file delivered through a download link; it is an estimate of transfer volume.',
      ),
    ),
    ui.panel(
      ui.node('h2', 'Plan features'),
      ui.details({
        largest_file: fmtBytes(o.limits.max_file_bytes),
        temporary_retention: `up to ${o.limits.max_retention_days} days`,
        persistent_sharing: yes(o.limits.persistent),
        upload_requests: yes(o.limits.upload_requests),
        branded_pages: yes(o.limits.branding),
        custom_domains: yes(o.limits.custom_domains),
        advanced_analytics: yes(o.limits.advanced_analytics),
      }),
    ),
    ui.panel(
      ui.node('h2', 'What sharing controls can and cannot do'),
      ui.node(
        'p',
        'View-only access cannot prevent screenshots, photos of the screen or other copying.',
      ),
      ui.node(
        'p',
        'Revoking a link stops future access through it. It cannot remove copies that were already downloaded.',
      ),
      ui.node(
        'p',
        'A short URL is not access control. Confidential links use unpredictable codes; passwords, expiry and recipient restrictions protect the content.',
      ),
    ),
  ];
}

// ---- documents --------------------------------------------------------------------------------------------
async function documents(openId) {
  if (openId) return documentDetail(openId);
  const rows = (await ui.api(`${P()}/documents`)).items;
  return [
    ui.panel(
      ui.node('h2', 'New document'),
      ui.fieldsForm(
        [
          { name: 'title', label: 'Title' },
          {
            name: 'require_approval',
            label: 'Publication',
            options: [
              ['no', 'Publish without approval'],
              ['yes', 'Require an approval before publishing'],
            ],
          },
        ],
        'Create document',
        async (d) => {
          const doc = await ui.api(`${P()}/documents`, 'POST', {
            title: d.title,
            require_approval: d.require_approval === 'yes',
          });
          await show('Documents', doc.id);
        },
      ),
    ),
    ui.panel(
      rows.length
        ? ui.table(
            ['Document', 'Draft', 'Published', ''],
            rows.map((d) => [
              d.title,
              d.has_draft ? when(d.draft_updated_at) : 'No draft',
              d.published_at ? when(d.published_at) : 'Not published',
              ui.button('Open', () => show('Documents', d.id)),
            ]),
          )
        : ui.empty('No documents yet.'),
    ),
  ];
}

async function documentDetail(id) {
  const d = await ui.api(`${P()}/documents/${enc(id)}`);
  const docLinks = (await ui.api(`${P()}/links?target_id=${enc(id)}`)).items;
  // Composer: a minimal editor that produces a PDF. Drafts it made can be reopened; other PDFs are edited in an external PDF editor.
  const titleInput = ui.node('input');
  titleInput.value = d.title;
  titleInput.setAttribute('aria-label', 'Document heading');
  const bodyInput = ui.node('textarea', undefined, 'composer');
  bodyInput.rows = 14;
  bodyInput.setAttribute('aria-label', 'Document text');
  bodyInput.placeholder = 'Write or edit the document text here, then save a draft.';
  const bar = progress();
  const saveDraft = async (file) => {
    await ownerUpload(file, { target: 'draft', document_id: id }, bar);
    bar.done('Saved. Checking the file…');
  };
  const pick = ui.node('input');
  pick.type = 'file';
  pick.accept = 'application/pdf,.pdf';
  pick.setAttribute('aria-label', 'Upload a PDF as the new draft');
  pick.addEventListener('change', async () => {
    if (!pick.files?.[0]) return;
    try {
      await saveDraft(pick.files[0]);
      await show('Documents', id);
      ui.notice(DRAFT_SAVED);
    } catch (e) {
      ui.errorMessage(e);
    }
  });
  const editor = ui.panel(
    ui.node('h2', 'Edit'),
    ui.node(
      'p',
      'Edits are saved as a private draft. Exporting creates an immutable version; only publishing changes what “latest” links serve.',
    ),
    titleInput,
    bodyInput,
    ui.node('div', undefined, 'actions'),
    bar.box,
  );
  editor.querySelector('.actions').append(
    ui.button(
      'Save draft',
      async () => {
        const bytes = composePdf({ title: titleInput.value || d.title, body: bodyInput.value });
        await saveDraft(
          new File([bytes], `${d.title}.pdf`, {
            type: 'application/pdf',
            lastModified: Date.now(),
          }),
        );
        await show('Documents', id);
        ui.notice(DRAFT_SAVED);
      },
      'primary',
    ),
    ...(d.has_draft
      ? [
          ui.button('Load draft into editor', async () => {
            const r = await ui.api(`${P()}/files/download`, 'POST', { type: 'draft', id });
            const bytes = new Uint8Array(
              await (await fetch(r.url, { credentials: 'omit' })).arrayBuffer(),
            );
            const src = composerSource(bytes);
            if (!src)
              return ui.notice(
                'This draft was not made with the composer. Edit it in your PDF editor and upload the result.',
                true,
              );
            titleInput.value = src.title;
            bodyInput.value = src.body;
            ui.notice('Draft loaded.');
          }),
          ui.button('Download draft', () => download('draft', id)),
        ]
      : []),
  );
  const uploadPdf = ui.node('label', 'Or upload a PDF edited in your PDF editor');
  uploadPdf.append(pick);
  editor.append(uploadPdf);

  const exportForm = ui.fieldsForm(
    [{ name: 'note', label: 'Version note', optional: true }],
    'Export new version',
    async (f) => {
      const v = await ui.api(
        `${P()}/documents/${enc(id)}/export`,
        'POST',
        f.note ? { note: f.note } : {},
      );
      await show('Documents', id);
      ui.notice(
        `Version ${v.number} exported. It is private until you publish or share it as a fixed version.`,
      );
    },
  );
  const versions = ui.panel(
    ui.node('h2', 'Versions'),
    d.draft_uploads.length
      ? ui.node(
          'p',
          `Draft upload status: ${d.draft_uploads.map((u) => u.status + (u.reject_reason ? ` (${u.reject_reason})` : '')).join(', ')}`,
        )
      : ui.node('span'),
    ...(d.has_draft ? [exportForm] : [ui.empty('Save a draft first.')]),
    d.versions.length
      ? ui.table(
          ['Version', 'Note', 'Exported', 'State', 'Review', ''],
          d.versions.map((v) => {
            const actions = ui.node('div', undefined, 'actions');
            actions.append(ui.button('Download', () => download('version', v.id)));
            if (!v.published)
              actions.append(
                ui.button('Publish', async () => {
                  const note = d.published_version_id
                    ? (prompt('Explain the change to recipients (optional):') ?? undefined)
                    : undefined;
                  await ui.api(`${P()}/documents/${enc(id)}/publish`, 'POST', {
                    version_id: v.id,
                    ...(note ? { replacement_note: note } : {}),
                  });
                  await show('Documents', id);
                  ui.notice(`Version ${v.number} is now the published version.`);
                }),
              );
            actions.append(
              ui.button('Share this version', () =>
                show('Share links', {
                  target_type: 'document',
                  target_id: id,
                  version_mode: 'fixed',
                  version_id: v.id,
                  label: `${d.title} v${v.number}`,
                }),
              ),
              ui.button('Review thread', async () => {
                const t = await ui.api(`${P()}/documents/${enc(id)}/versions/${enc(v.id)}/review`);
                ui.modal(
                  ui.node('h2', `Review · version ${v.number}`),
                  ...(t.comments.length
                    ? t.comments.map((c) =>
                        ui.node('p', `${c.author}${c.page ? ` (page ${c.page})` : ''}: ${c.body}`),
                      )
                    : [ui.empty('No comments.')]),
                  ...t.reviews.map((r) =>
                    ui.node(
                      'p',
                      `${r.reviewer}: ${r.decision.replace('_', ' ')}${r.note ? ` — ${r.note}` : ''}`,
                    ),
                  ),
                );
              }),
            );
            return [
              `v${v.number}`,
              v.note || '—',
              when(v.created_at),
              ui.node(
                'span',
                v.published ? 'published' : 'private',
                v.published ? 'badge' : 'badge inactive',
              ),
              `${v.approvals} approved · ${v.changes_requested} changes`,
              actions,
            ];
          }),
        )
      : ui.empty('No versions yet.'),
  );
  const sharing = ui.panel(
    ui.node('h2', 'Links to this document'),
    ui.node('div', undefined, 'actions'),
    docLinks.length
      ? ui.table(
          ['Link', 'Serves', 'Permission', 'State', ''],
          docLinks.map((l) => [
            l.label || l.id,
            l.version_mode === 'fixed'
              ? `Fixed version ${l.serves_version}`
              : `Latest published${l.serves_version ? ` (v${l.serves_version})` : ' (none yet)'}`,
            l.permission,
            ui.badge(l.state),
            ui.button('Manage', () => show('Share links', l.id)),
          ]),
        )
      : ui.empty('Not shared yet.'),
  );
  sharing.querySelector('.actions').append(
    ui.button(
      'Share latest published version',
      () =>
        show('Share links', {
          target_type: 'document',
          target_id: id,
          version_mode: 'latest',
          label: d.title,
        }),
      'primary',
    ),
  );
  return [
    ui.panel(
      ui.button('← All documents', () => show('Documents')),
      ui.node('h2', d.title),
      ui.node(
        'p',
        d.require_approval
          ? 'Publication requires an approval from a reviewer other than the author.'
          : 'Publication is explicit; nothing becomes public automatically.',
      ),
    ),
    editor,
    versions,
    sharing,
    ui.panel(
      ui.button(
        'Delete document',
        async () => {
          if (!confirm('Delete this document, its versions and their links?')) return;
          await ui.api(`${P()}/documents/${enc(id)}/delete`, 'POST', {});
          await show('Documents');
        },
        'danger',
      ),
    ),
  ];
}

// ---- transfers --------------------------------------------------------------------------------------------
async function transfers(openId) {
  if (openId) return transferDetail(openId);
  const rows = (await ui.api(`${P()}/transfers`)).items;
  return [
    ui.panel(
      ui.node('h2', 'New transfer'),
      ui.fieldsForm(
        [
          { name: 'title', label: 'Title' },
          { name: 'message', label: 'Message to recipients', optional: true },
          {
            name: 'kind',
            label: 'Kind',
            options: [
              ['temporary', 'Temporary (files deleted at expiry)'],
              ['persistent', 'Persistent (plan feature)'],
            ],
          },
          { name: 'days', label: 'Days until expiry', type: 'number', value: '7', min: 1 },
        ],
        'Create transfer',
        async (f) => {
          const t = await ui.api(`${P()}/transfers`, 'POST', {
            title: f.title,
            ...(f.message ? { message: f.message } : {}),
            kind: f.kind,
            expires_at: inDays(f.days),
          });
          await show('Transfers', t.id);
        },
      ),
    ),
    ui.panel(
      rows.length
        ? ui.table(
            ['Transfer', 'Kind', 'State', 'Expires', ''],
            rows.map((t) => [
              t.title,
              t.kind,
              ui.badge(t.status),
              when(t.expires_at),
              ui.button('Open', () => show('Transfers', t.id)),
            ]),
          )
        : ui.empty('No transfers yet.'),
    ),
  ];
}

async function transferDetail(id) {
  const t = await ui.api(`${P()}/transfers/${enc(id)}`);
  const list = ui.node('div');
  const files = ui.node('input');
  files.type = 'file';
  files.multiple = true;
  files.setAttribute('aria-label', 'Choose files');
  const folder = ui.node('input');
  folder.type = 'file';
  folder.webkitdirectory = true;
  folder.setAttribute('aria-label', 'Choose a folder');
  const run = async (input) => {
    for (const file of input.files ?? []) {
      const bar = progress();
      list.append(ui.node('p', file.webkitRelativePath || file.name), bar.box);
      const path = file.webkitRelativePath
        ? file.webkitRelativePath.split('/').slice(0, -1).join('/')
        : undefined;
      try {
        await ownerUpload(
          file,
          { target: 'transfer', transfer_id: id, ...(path ? { folder_path: path } : {}) },
          bar,
        );
        bar.done('Uploaded · checking');
      } catch (e) {
        bar.done(e.message);
      }
    }
    await show('Transfers', id);
  };
  files.addEventListener('change', () => run(files));
  folder.addEventListener('change', () => run(folder));
  const fileRows = t.files.map((f) => {
    const actions = ui.node('div', undefined, 'actions');
    if (f.status === 'available')
      actions.append(ui.button('Download', () => download('transfer_file', f.id)));
    const replace = ui.node('input');
    replace.type = 'file';
    replace.setAttribute('aria-label', `Replace ${f.name}`);
    replace.addEventListener('change', async () => {
      const file = replace.files?.[0];
      if (!file) return;
      const note = prompt('Explain the replacement to recipients (optional):') ?? '';
      const bar = progress();
      actions.append(bar.box);
      try {
        await ownerUpload(
          file,
          { target: 'replace', transfer_id: id, file_id: f.id, ...(note ? { note } : {}) },
          bar,
          f.name,
        );
        await show('Transfers', id);
        ui.notice(
          'Replacement uploaded. The link keeps serving the current file until the new one passes checks.',
        );
      } catch (e) {
        ui.errorMessage(e);
      }
    });
    const rl = ui.node('label', 'Replace');
    rl.append(replace);
    actions.append(
      rl,
      ui.button('Remove', async () => {
        await ui.api(`${P()}/transfers/${enc(id)}/files/${enc(f.id)}/remove`, 'POST', {});
        await show('Transfers', id);
      }),
    );
    return [
      f.folder_path ? `${f.folder_path}/${f.name}` : f.name,
      fmtBytes(f.size),
      ui.badge(f.status === 'available' ? 'active' : f.status),
      f.revision > 1
        ? `rev ${f.revision}${f.replacement_note ? ` · ${f.replacement_note}` : ''}`
        : '—',
      actions,
    ];
  });
  const uploads = ui.panel(
    ui.node('h2', 'Add files'),
    ui.node(
      'p',
      'Uploads go directly to private storage and resume if interrupted: choose the same file again to continue.',
    ),
  );
  const a = ui.node('label', 'Files');
  a.append(files);
  const b = ui.node('label', 'Folder');
  b.append(folder);
  uploads.append(a, b, list);
  return [
    ui.panel(
      ui.button('← All transfers', () => show('Transfers')),
      ui.node('h2', t.title),
      ui.details({
        kind: t.kind,
        state: t.status,
        expires: when(t.expires_at),
        files_deleted_at: t.files_deleted_at
          ? when(t.files_deleted_at)
          : 'kept until you delete the transfer',
      }),
    ),
    ...(t.status === 'active' ? [uploads] : []),
    ui.panel(
      ui.node('h2', 'Files'),
      t.files.length
        ? ui.table(['File', 'Size', 'Status', 'Revision', ''], fileRows)
        : ui.empty('No files yet.'),
    ),
    ui.panel(
      ui.node('h2', 'Share'),
      ...(t.status === 'active'
        ? [
            ui.button(
              'Create a share link',
              () => show('Share links', { target_type: 'transfer', target_id: id, label: t.title }),
              'primary',
            ),
          ]
        : []),
      ui.button(
        'Revoke transfer',
        async () => {
          if (
            !confirm(
              'Revoke every link to this transfer? Copies already downloaded cannot be recalled.',
            )
          )
            return;
          await ui.api(`${P()}/transfers/${enc(id)}/revoke`, 'POST', {});
          await show('Transfers', id);
        },
        'danger',
      ),
      ui.button(
        'Delete transfer',
        async () => {
          if (!confirm('Delete this transfer and its files?')) return;
          await ui.api(`${P()}/transfers/${enc(id)}/delete`, 'POST', {});
          await show('Transfers');
        },
        'danger',
      ),
    ),
  ];
}

// ---- share links -----------------------------------------------------------------------------------------
async function links(arg) {
  if (typeof arg === 'string') return linkDetail(arg);
  const rows = (await ui.api(`${P()}/links`)).items;
  const out = [];
  if (arg && typeof arg === 'object') out.push(linkForm(arg));
  out.push(
    ui.panel(
      rows.length
        ? ui.table(
            ['Link', 'Target', 'Serves', 'Access', 'State', ''],
            rows.map((l) => [
              l.label || l.id,
              l.target_type,
              l.target_type === 'document'
                ? l.version_mode === 'fixed'
                  ? `Fixed v${l.serves_version}`
                  : `Latest published${l.serves_version ? ` (v${l.serves_version})` : ''}`
                : 'Files',
              `${l.permission}${l.has_password ? ' · password' : ''}${l.restriction !== 'none' ? ` · ${l.restriction}` : ''}`,
              ui.badge(l.state),
              ui.button('Manage', () => show('Share links', l.id)),
            ]),
          )
        : ui.empty('No share links yet. Create one from a document or transfer.'),
    ),
  );
  return out;
}

function linkForm(target) {
  return ui.panel(
    ui.node('h2', `Share ${target.label || ''}`),
    target.version_mode
      ? ui.node(
          'p',
          target.version_mode === 'fixed'
            ? 'This link will always serve this exact version.'
            : 'This link follows the version you publish. Unpublished edits never appear.',
        )
      : ui.node('span'),
    ui.fieldsForm(
      [
        {
          name: 'permission',
          label: 'Access',
          options: [
            ['download', 'View and download'],
            ['view', 'View only (cannot stop screenshots or copying)'],
            ...(target.target_type === 'document'
              ? [['review', 'Review: comment and approve (signed-in recipients)']]
              : []),
          ],
        },
        {
          name: 'restriction',
          label: 'Who can open it',
          options: [
            ['none', 'Anyone with the link'],
            ['members', 'Members of this workspace'],
            ['recipients', 'Named recipients (verified accounts)'],
          ],
        },
        { name: 'recipients', label: 'Recipient emails, comma separated', optional: true },
        {
          name: 'password',
          label: 'Password (optional, 8+ characters)',
          type: 'password',
          optional: true,
          autocomplete: 'new-password',
        },
        {
          name: 'days',
          label: 'Expires after days (optional)',
          type: 'number',
          optional: true,
          min: 1,
        },
        {
          name: 'max_downloads',
          label: 'Download limit (optional)',
          type: 'number',
          optional: true,
          min: 1,
        },
        {
          name: 'notify',
          label: 'Notify me',
          options: [
            ['no', 'No notifications'],
            ['yes', 'Notify me on access, download and acknowledgement'],
          ],
        },
      ],
      'Create share link',
      async (f) => {
        const body = {
          target_type: target.target_type,
          target_id: target.target_id,
          ...(target.version_mode ? { version_mode: target.version_mode } : {}),
          ...(target.version_id ? { version_id: target.version_id } : {}),
          permission: f.permission,
          restriction: f.restriction,
          ...(f.restriction === 'recipients'
            ? {
                recipients: (f.recipients || '')
                  .split(',')
                  .map((s) => s.trim())
                  .filter(Boolean),
              }
            : {}),
          ...(f.password ? { password: f.password } : {}),
          ...(f.days ? { expires_at: inDays(f.days) } : {}),
          ...(f.max_downloads ? { max_downloads: f.max_downloads } : {}),
          notify_on_access: f.notify === 'yes',
          ...(target.label ? { label: target.label } : {}),
        };
        const l = await ui.api(`${P()}/links`, 'POST', body);
        await show('Share links', l.id);
      },
    ),
  );
}

async function linkDetail(id) {
  const [l, act] = await Promise.all([
    ui.api(`${P()}/links/${enc(id)}`),
    ui.api(`${P()}/links/${enc(id)}/activity`),
  ]);
  const status = (action) => async () => {
    const reason = action === 'revoke' ? (prompt('Reason (optional):') ?? undefined) : undefined;
    await ui.api(`${P()}/links/${enc(id)}/status`, 'POST', {
      action,
      ...(reason ? { reason } : {}),
    });
    await show('Share links', id);
  };
  const totals = Object.entries(act.totals).map(([k, v]) => [k, v.count, v.bots]);
  return [
    ui.panel(
      ui.button('← All share links', () => show('Share links')),
      ui.node('h2', l.label || 'Share link'),
      copyField(l.url, 'Share link URL'),
      ui.details({
        state: l.state,
        serves:
          l.target_type === 'document'
            ? l.version_mode === 'fixed'
              ? `fixed version ${l.serves_version}`
              : `latest published version${l.serves_version ? ` (v${l.serves_version})` : ' — none published yet'}`
            : 'transfer files',
        permission: l.permission,
        access:
          l.restriction === 'recipients' ? `recipients: ${l.recipients.join(', ')}` : l.restriction,
        password: l.has_password ? 'yes' : 'no',
        expires: when(l.expires_at),
        downloads: l.max_downloads
          ? `${l.download_count} of ${l.max_downloads}`
          : String(l.download_count),
      }),
      ui.node('div', undefined, 'actions'),
    ),
    ui.panel(
      ui.node('h2', 'Short link and QR code'),
      ui.button('Create confidential short link', async () => {
        const s = await ui.api(`${P()}/short-links`, 'POST', {
          kind: 'confidential',
          destination_type: 'share',
          target_id: id,
          label: l.label || undefined,
        });
        await show('Short links', s.id);
      }),
      ui.node(
        'p',
        'Confidential short links use an unpredictable code. The share link’s password, expiry and recipients still apply.',
      ),
    ),
    ui.panel(
      ui.node('h2', 'Delivery receipts'),
      ...act.notes.map((n) => ui.node('p', n)),
      totals.length
        ? ui.table(['Event', 'Count', 'Likely automated'], totals)
        : ui.empty('No activity yet.'),
      act.events.length
        ? ui.table(
            ['When', 'Event', 'Who', 'Automated?'],
            act.events.map((e) => [
              when(e.at),
              e.kind,
              e.identity
                ? e.identity.email
                  ? `${e.identity.email} (signed in)`
                  : `${e.identity.name} (unverified name)`
                : 'Anonymous',
              e.likely_automated ? 'likely' : 'no',
            ]),
          )
        : ui.node('span'),
    ),
  ].map((p, i) => {
    if (i === 0) {
      const actions = p.querySelector('.actions');
      if (l.status === 'active')
        actions.append(
          ui.button('Suspend', status('suspend')),
          ui.button('Revoke', status('revoke'), 'danger'),
        );
      else if (l.status === 'suspended')
        actions.append(
          ui.button('Resume', status('resume')),
          ui.button('Revoke', status('revoke'), 'danger'),
        );
    }
    return p;
  });
}

// ---- short links -----------------------------------------------------------------------------------------
async function shortLinks(openId) {
  if (openId) return shortDetail(openId);
  const q = ui.node('input');
  q.type = 'search';
  q.placeholder = 'Search code, label or destination';
  q.setAttribute('aria-label', 'Search short links');
  const results = ui.node('div');
  const selected = new Set();
  const load = async () => {
    const rows = (await ui.api(`${P()}/short-links${q.value ? `?q=${enc(q.value)}` : ''}`)).items;
    results.replaceChildren(
      rows.length
        ? ui.table(
            ['', 'Short link', 'Kind', 'Destination', 'Folder / tags', 'State', ''],
            rows.map((s) => {
              const box = ui.node('input');
              box.type = 'checkbox';
              box.setAttribute('aria-label', `Select ${s.url}`);
              box.addEventListener('change', () =>
                box.checked ? selected.add(s.id) : selected.delete(s.id),
              );
              return [
                box,
                s.url,
                s.kind,
                s.destination_url || `${s.destination_type} link`,
                [s.folder, ...s.tags].filter(Boolean).join(' · ') || '—',
                ui.badge(s.state),
                ui.button('Manage', () => show('Short links', s.id)),
              ];
            }),
          )
        : ui.empty('No short links.'),
    );
  };
  q.addEventListener('input', () => void load().catch(ui.errorMessage));
  await load();
  const bulk =
    (action, extra = {}) =>
    async () => {
      if (!selected.size) return ui.notice('Select links first.', true);
      await ui.api(`${P()}/short-links/bulk`, 'POST', { ids: [...selected], action, ...extra });
      await show('Short links');
    };
  const bulkBar = ui.node('div', undefined, 'actions');
  bulkBar.append(
    ui.button('Suspend selected', bulk('suspend')),
    ui.button('Resume selected', bulk('resume')),
    ui.button('Move selected…', async () =>
      bulk('move', { folder: prompt('Folder name:') ?? '' })(),
    ),
    ui.button('Tag selected…', async () => bulk('tag', { tag: prompt('Tag:') ?? '' })()),
    ui.button('Revoke selected', bulk('revoke'), 'danger'),
  );
  return [
    ui.panel(
      ui.node('h2', 'New public short link'),
      ui.node(
        'p',
        'Public links are for marketing pages and other public web addresses. For documents, create a confidential short link from the share link instead.',
      ),
      ui.fieldsForm(
        [
          { name: 'destination_url', label: 'Destination (https://…)', type: 'url' },
          { name: 'alias', label: 'Custom alias (optional)', optional: true },
          { name: 'folder', label: 'Folder (optional)', optional: true },
          { name: 'tags', label: 'Tags, comma separated (optional)', optional: true },
          {
            name: 'days',
            label: 'Expires after days (optional)',
            type: 'number',
            optional: true,
            min: 1,
          },
        ],
        'Create short link',
        async (f) => {
          const s = await ui.api(`${P()}/short-links`, 'POST', {
            kind: 'public',
            destination_type: 'external',
            destination_url: f.destination_url,
            ...(f.alias ? { alias: f.alias } : {}),
            ...(f.folder ? { folder: f.folder } : {}),
            ...(f.tags
              ? {
                  tags: f.tags
                    .split(',')
                    .map((t) => t.trim())
                    .filter(Boolean),
                }
              : {}),
            ...(f.days ? { expires_at: inDays(f.days) } : {}),
          });
          await show('Short links', s.id);
        },
      ),
    ),
    ui.panel(q, bulkBar, results),
  ];
}

async function shortDetail(id) {
  const [s, hist, stats] = await Promise.all([
    ui.api(`${P()}/short-links/${enc(id)}`),
    ui.api(`${P()}/short-links/${enc(id)}/history`),
    ui.api(`${P()}/short-links/${enc(id)}/stats`),
  ]);
  const qrUrl = `${P()}/short-links/${enc(id)}/qr.svg`;
  const img = ui.node('img');
  img.alt = `QR code for ${s.url}`;
  img.width = 200;
  img.height = 200;
  const blob = await ui.blob(qrUrl);
  const objectUrl = URL.createObjectURL(blob);
  img.src = objectUrl;
  const dl = ui.node('a', 'Download QR code (SVG)');
  dl.href = objectUrl;
  dl.download = `qr-${s.code || s.id}.svg`;
  const status = (action) => async () => {
    await ui.api(`${P()}/short-links/${enc(id)}/status`, 'POST', { action });
    await show('Short links', id);
  };
  const actions = ui.node('div', undefined, 'actions');
  if (s.status === 'active')
    actions.append(
      ui.button('Suspend', status('suspend')),
      ui.button('Revoke', status('revoke'), 'danger'),
    );
  if (s.status === 'suspended' && !s.operator_hold)
    actions.append(ui.button('Resume', status('resume')));
  if (s.operator_hold)
    actions.append(ui.node('p', 'Suspended by the platform after an abuse review.'));
  return [
    ui.panel(
      ui.button('← All short links', () => show('Short links')),
      ui.node('h2', s.label || s.url),
      copyField(s.url, 'Short URL'),
      ui.details({
        kind: s.kind,
        state: s.state,
        destination: s.destination_url || `${s.destination_type} ${s.target_id}`,
        expires: when(s.expires_at),
        folder: s.folder || '—',
        tags: s.tags.join(', ') || '—',
      }),
      actions,
    ),
    ui.panel(ui.node('h2', 'QR code'), img, dl),
    ...(s.kind === 'public'
      ? [
          ui.panel(
            ui.node('h2', 'Change destination'),
            ui.fieldsForm(
              [
                {
                  name: 'destination_url',
                  label: 'New destination',
                  type: 'url',
                  value: s.destination_url,
                },
                { name: 'reason', label: 'Reason (kept in the history)', optional: true },
              ],
              'Update destination',
              async (f) => {
                await ui.api(`${P()}/short-links/${enc(id)}`, 'PATCH', f);
                await show('Short links', id);
              },
            ),
          ),
        ]
      : []),
    ui.panel(
      ui.node('h2', 'Destination history'),
      ui.table(
        ['When', 'Destination', 'By', 'Reason'],
        hist.items.map((h) => [
          when(h.created_at),
          h.destination_url || `${h.destination_type} ${h.target_id}`,
          h.changed_by,
          h.reason || '—',
        ]),
      ),
    ),
    ui.panel(
      ui.node('h2', 'Visits (last 90 days)'),
      ...stats.notes.map((n) => ui.node('p', n)),
      stats.daily.length
        ? ui.table(
            ['Day', 'Visits', 'Likely automated'],
            stats.daily.map((d) => [d.day, d.visits, d.bots]),
          )
        : ui.empty('No visits yet.'),
      stats.referrers
        ? stats.referrers.length
          ? ui.table(
              ['Referring site (approximate)', 'Visits'],
              stats.referrers.map((r) => [r.host, r.count]),
            )
          : ui.empty('No referral information.')
        : ui.node('p', 'Referral breakdown is available with advanced analytics.'),
    ),
  ];
}

// ---- upload requests -------------------------------------------------------------------------------------
async function requests(openId) {
  if (openId) return requestDetail(openId);
  const rows = (await ui.api(`${P()}/upload-requests`)).items;
  return [
    ui.panel(
      ui.node('h2', 'Request files'),
      ui.node(
        'p',
        'People you send the link to can upload files for you. They see only their own uploads.',
      ),
      ui.fieldsForm(
        [
          { name: 'title', label: 'Title' },
          { name: 'instructions', label: 'Instructions', optional: true },
          {
            name: 'items',
            label: 'Required files, one label per comma (e.g. Passport scan, Signed contract)',
          },
          {
            name: 'accept',
            label: 'Accepted types',
            options: [
              ['pdf', 'PDF only'],
              ['pdf,png,jpg,jpeg', 'PDF and images'],
              ['', 'Any permitted format'],
            ],
          },
          { name: 'days', label: 'Deadline in days', type: 'number', value: '14', min: 1 },
          { name: 'max_mb', label: 'Largest file (MB)', type: 'number', value: '25', min: 1 },
          {
            name: 'password',
            label: 'Password (optional)',
            type: 'password',
            optional: true,
            autocomplete: 'new-password',
          },
          {
            name: 'notify',
            label: 'Notify me',
            options: [
              ['yes', 'Email me when a submission arrives'],
              ['no', 'In-app only'],
            ],
          },
        ],
        'Create upload request',
        async (f) => {
          const labels = f.items
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
          const r = await ui.api(`${P()}/upload-requests`, 'POST', {
            title: f.title,
            ...(f.instructions ? { instructions: f.instructions } : {}),
            requirements: labels.map((label, i) => ({
              key: `item-${i + 1}`,
              label,
              required: true,
              max_files: 5,
              ...(f.accept ? { accept: f.accept.split(',') } : {}),
            })),
            deadline: inDays(f.days),
            max_file_bytes: f.max_mb * 1024 * 1024,
            max_total_bytes: f.max_mb * 1024 * 1024 * 10,
            ...(f.password ? { password: f.password } : {}),
            notify: f.notify === 'yes',
          });
          await show('Upload requests', r.id);
        },
      ),
    ),
    ui.panel(
      rows.length
        ? ui.table(
            ['Request', 'Deadline', 'State', ''],
            rows.map((r) => [
              r.title,
              when(r.deadline),
              ui.badge(r.accepting ? 'active' : r.status),
              ui.button('Open', () => show('Upload requests', r.id)),
            ]),
          )
        : ui.empty('No upload requests yet.'),
    ),
  ];
}

async function requestDetail(id) {
  const r = await ui.api(`${P()}/upload-requests/${enc(id)}`);
  return [
    ui.panel(
      ui.button('← All upload requests', () => show('Upload requests')),
      ui.node('h2', r.title),
      copyField(r.url, 'Upload request URL'),
      ui.details({
        accepting: r.accepting ? 'yes' : 'no',
        deadline: when(r.deadline),
        largest_file: fmtBytes(r.max_file_bytes),
        files_deleted_after: r.delete_after
          ? when(r.delete_after)
          : 'kept until you delete the request',
      }),
      ui.button('Create confidential short link', async () => {
        const s = await ui.api(`${P()}/short-links`, 'POST', {
          kind: 'confidential',
          destination_type: 'request',
          target_id: id,
          label: r.title,
        });
        await show('Short links', s.id);
      }),
      ...(r.status === 'open'
        ? [
            ui.button(
              'Close request',
              async () => (
                await ui.api(`${P()}/upload-requests/${enc(id)}/status`, 'POST', {
                  action: 'close',
                }),
                show('Upload requests', id)
              ),
            ),
          ]
        : []),
      ui.button(
        'Delete request and files',
        async () => {
          if (!confirm('Delete this request and every uploaded file?')) return;
          await ui.api(`${P()}/upload-requests/${enc(id)}/status`, 'POST', { action: 'delete' });
          await show('Upload requests');
        },
        'danger',
      ),
    ),
    ui.panel(
      ui.node('h2', 'Submissions'),
      ui.node('p', 'Names and emails are typed by the submitter and are not verified.'),
      r.submissions.length
        ? ui.table(
            ['From', 'State', 'Files'],
            r.submissions.map((s) => {
              const filesBox = ui.node('div');
              for (const f of s.files) {
                const row = ui.node(
                  'div',
                  `${f.name} · ${fmtBytes(f.size)} · ${f.status}${f.reject_reason ? ` (${f.reject_reason})` : ''} `,
                );
                if (f.status === 'available')
                  row.append(ui.button('Download', () => download('submission_file', f.id)));
                filesBox.append(row);
              }
              return [
                `${s.submitter_name}${s.submitter_email ? ` <${s.submitter_email}>` : ''}`,
                s.status,
                filesBox,
              ];
            }),
          )
        : ui.empty('No submissions yet.'),
    ),
  ];
}

// ---- notifications ---------------------------------------------------------------------------------------
async function notifications() {
  const rows = (await ui.api(`${P()}/notifications`)).items;
  const unread = rows.filter((n) => !n.read).map((n) => n.id);
  return [
    ui.panel(
      ...(unread.length
        ? [
            ui.button(
              'Mark all read',
              async () => (
                await ui.api(`${P()}/notifications/read`, 'POST', { ids: unread.slice(0, 100) }),
                show('Notifications')
              ),
            ),
          ]
        : []),
      rows.length
        ? ui.table(
            ['When', 'Notification', ''],
            rows.map((n) => [when(n.created_at), n.message, n.read ? '' : ui.badge('new')]),
          )
        : ui.empty('No notifications.'),
    ),
  ];
}
