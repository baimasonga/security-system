import {
  api,
  brand,
  button,
  content,
  fmtBytes,
  form,
  node,
  notice,
  panel,
  signIn,
  state,
  wireReport,
} from './public.mjs';

const token = location.pathname.split('/').pop();
const base = `/v1/public/shares/${encodeURIComponent(token)}`;
let password = '';
let manifest;

const STATES = {
  revoked: 'The sender revoked this link.',
  suspended: 'This link is suspended.',
  expired: 'This link has expired.',
  unavailable: 'The shared files are no longer available.',
  not_published: 'The sender has not published this document yet.',
  download_limit_reached: 'The download limit for this link has been reached.',
};

async function open() {
  try {
    manifest = await api(`${base}/open`, 'POST', password ? { password } : {});
    render();
  } catch (e) {
    if (e.code === 'password_required') return askPassword(e.message === 'incorrect password');
    if (e.code === 'unauthenticated') return content().replaceChildren(signIn(open));
    if (e.code === 'link_unavailable')
      return content().replaceChildren(
        panel(
          node('h1', 'Link unavailable'),
          node('p', STATES[e.details?.state] || 'This link is not available.'),
        ),
      );
    if (e.status === 404)
      return content().replaceChildren(
        panel(node('h1', 'Link not found'), node('p', 'Check that you copied the whole link.')),
      );
    content().replaceChildren(panel(node('h1', 'Could not open the link'), node('p', e.message)));
  }
}

function askPassword(wrong) {
  content().replaceChildren(
    panel(
      node('h1', 'Password required'),
      node(
        'p',
        wrong
          ? 'That password was not correct.'
          : 'The sender protected this link with a password.',
      ),
      form(
        [
          {
            name: 'password',
            label: 'Password',
            type: 'password',
            autocomplete: 'current-password',
          },
        ],
        'Open',
        async (v) => {
          password = v.password;
          await open();
        },
      ),
    ),
  );
}

async function fileUrl(fileId, disposition) {
  try {
    return (
      await api(`${base}/files/url`, 'POST', {
        grant: manifest.grant,
        file_id: fileId,
        disposition,
      })
    ).url;
  } catch (e) {
    if (e.code === 'unauthenticated' && /expired/.test(e.message)) {
      await open();
      notice('Your access was refreshed. Try again.');
      return undefined;
    }
    throw e;
  }
}

function render() {
  const m = manifest;
  const head = panel(brand(m.branding), node('h1', m.title));
  if (m.message) head.append(node('p', m.message));
  if (m.kind === 'document') {
    head.append(
      node('p', m.version.label, m.version.mode === 'fixed' ? 'badge' : 'badge inactive'),
    );
    if (m.version.published_at)
      head.append(node('p', `Published ${new Date(m.version.published_at).toLocaleString()}`));
    if (m.version.replacement_note)
      head.append(node('p', `What changed: ${m.version.replacement_note}`, 'replacement'));
    if (m.history?.length > 1)
      head.append(
        node(
          'p',
          `Earlier published versions: ${m.history
            .slice(1)
            .map((h) => `v${h.number}`)
            .join(', ')}`,
        ),
      );
  }
  if (m.expires_at)
    head.append(node('p', `Available until ${new Date(m.expires_at).toLocaleString()}`));
  if (m.downloads_remaining !== null)
    head.append(node('p', `Downloads remaining: ${m.downloads_remaining}`));

  const list = node('ul', undefined, 'file-list');
  for (const f of m.files) {
    const li = node('li');
    li.append(
      node('strong', f.folder_path ? `${f.folder_path}/${f.name}` : f.name),
      node('span', ` · ${fmtBytes(f.size)}`),
    );
    if (f.replacement_note) li.append(node('p', `Replaced: ${f.replacement_note}`, 'replacement'));
    if (f.status !== 'available')
      li.append(
        node(
          'span',
          f.status === 'processing' ? ' · being checked, available shortly' : ` · ${f.status}`,
          'badge inactive',
        ),
      );
    const actions = node('div', undefined, 'actions');
    if (f.viewable)
      actions.append(
        button('View', async () => {
          const url = await fileUrl(f.id, 'inline');
          if (url) window.open(url, '_blank', 'noopener,noreferrer');
        }),
      );
    if (f.downloadable)
      actions.append(
        button(
          'Download',
          async () => {
            const url = await fileUrl(f.id, 'attachment');
            if (url) location.assign(url);
          },
          'primary',
        ),
      );
    li.append(actions);
    list.append(li);
  }
  const files = panel(node('h2', m.kind === 'document' ? 'Document' : 'Files'), list);

  const ack = panel(
    node('h2', 'Confirm receipt'),
    node(
      'p',
      'Let the sender know you received this. A visit or download alone is not a confirmation.',
    ),
  );
  ack.append(
    state.session
      ? button('I confirm receipt', async () => {
          await api(`${base}/acknowledge`, 'POST', { grant: m.grant });
          notice('Receipt confirmed.');
        })
      : form(
          [{ name: 'name', label: 'Your name (shown to the sender as unverified)' }],
          'I confirm receipt',
          async (v) => {
            await api(`${base}/acknowledge`, 'POST', { grant: m.grant, declared_name: v.name });
            notice('Receipt confirmed.');
          },
        ),
  );
  const parts = [head, files];
  if (m.permission === 'review') parts.push(reviewPanel());
  parts.push(ack, panel(...m.notices.map((n) => node('p', n, 'fine-print'))));
  content().replaceChildren(...parts);
}

function reviewPanel() {
  const box = panel(node('h2', 'Review'));
  const thread = node('div');
  const load = async () => {
    const t = await api(`${base}/comments`, 'GET', undefined, { 'x-share-grant': manifest.grant });
    thread.replaceChildren(
      ...(t.comments.length
        ? t.comments.map((c) =>
            node('p', `${c.author}${c.page ? ` · page ${c.page}` : ''}: ${c.body}`),
          )
        : [node('p', 'No comments yet.')]),
      ...t.reviews.map((r) => node('p', `${r.reviewer}: ${r.decision.replace('_', ' ')}`, 'badge')),
    );
  };
  void load().catch((e) => notice(e.message, true));
  box.append(
    thread,
    form(
      [
        { name: 'body', label: 'Comment', multiline: true },
        { name: 'page', label: 'Page (optional)', type: 'number', optional: true },
      ],
      'Add comment',
      async (v) => {
        await api(`${base}/comments`, 'POST', {
          grant: manifest.grant,
          body: v.body,
          ...(v.page ? { page: Number(v.page) } : {}),
        });
        await load();
      },
    ),
    button(
      'Approve this version',
      async () => {
        await api(`${base}/review`, 'POST', { grant: manifest.grant, decision: 'approved' });
        await load();
      },
      'primary',
    ),
    button('Request changes', async () => {
      await api(`${base}/review`, 'POST', { grant: manifest.grant, decision: 'changes_requested' });
      await load();
    }),
  );
  return box;
}

wireReport();
void open();
