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
  wireReport,
} from './public.mjs';
import { fileKey, uploadFile } from './uploader.mjs';

const token = location.pathname.split('/').pop();
const base = `/v1/public/upload-requests/${encodeURIComponent(token)}`;
// The submission secret is held in memory only (never in browser storage): an interrupted upload resumes within this
// page, but a reload starts a new submission. It grants access only to this submitter's own files.
let info;
let secret = '';
let password = '';
const remember = (v) => {
  secret = v;
};
const h = () => ({ 'x-submission-secret': secret });

const STATES = {
  closed: 'This request is closed.',
  deadline_passed: 'The deadline for this request has passed.',
  suspended: 'This request is suspended.',
};

async function open() {
  try {
    info = await api(`${base}/open`, 'POST', password ? { password } : {});
  } catch (e) {
    if (e.code === 'password_required')
      return content().replaceChildren(
        panel(
          node('h1', 'Password required'),
          node(
            'p',
            e.message === 'incorrect password'
              ? 'That password was not correct.'
              : 'The requester protected this page with a password.',
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
    if (e.code === 'link_unavailable')
      return content().replaceChildren(
        panel(
          node('h1', 'Not accepting files'),
          node('p', STATES[e.details?.state] || 'This request is not available.'),
        ),
      );
    return content().replaceChildren(
      panel(node('h1', 'Request not found'), node('p', 'Check that you copied the whole link.')),
    );
  }
  start();
}

function intro() {
  const p = panel(brand(info.branding), node('h1', info.title));
  if (info.instructions) p.append(node('p', info.instructions));
  p.append(
    node(
      'p',
      `Deadline: ${new Date(info.deadline).toLocaleString()} · Largest file ${fmtBytes(info.max_file_bytes)}`,
    ),
  );
  for (const n of info.notices) p.append(node('p', n, 'fine-print'));
  return p;
}

function start() {
  content().replaceChildren(
    intro(),
    panel(
      node('h2', 'Who is sending these files?'),
      form(
        [
          { name: 'name', label: 'Your name', autocomplete: 'name' },
          {
            name: 'email',
            label: 'Your email (optional)',
            type: 'email',
            optional: true,
            autocomplete: 'email',
          },
        ],
        'Start',
        async (v) => {
          const r = await api(`${base}/submissions`, 'POST', {
            grant: info.grant,
            name: v.name,
            ...(v.email ? { email: v.email } : {}),
          });
          secret = r.submission_secret;
          remember(secret);
          await render(await api(`${base}/submission`, 'GET', undefined, h()));
        },
      ),
    ),
  );
}

async function render(sub) {
  if (sub.status === 'submitted') {
    remember('');
    return content().replaceChildren(
      intro(),
      panel(node('h1', 'Files sent'), node('p', 'Thank you. The requester has been notified.')),
    );
  }
  const reqs = panel(node('h2', 'Files'));
  for (const r of info.requirements) {
    const mine = sub.files.filter((f) => f.requirement_key === r.key);
    const row = node('div', undefined, 'requirement');
    row.append(
      node('h3', `${r.label}${r.required ? ' (required)' : ''}`),
      node('p', `Accepted: ${r.accept.join(', ')} · up to ${r.max_files} file(s)`, 'fine-print'),
    );
    for (const f of mine)
      row.append(
        node(
          'p',
          `${f.name} · ${fmtBytes(f.size)} · ${f.status === 'processing' ? 'received, being checked' : f.status}`,
        ),
      );
    if (mine.length < r.max_files) {
      const input = node('input');
      input.type = 'file';
      input.accept = r.accept.map((x) => `.${x}`).join(',');
      input.setAttribute('aria-label', `Upload ${r.label}`);
      const bar = node('progress');
      bar.max = 100;
      bar.value = 0;
      input.addEventListener('change', async () => {
        const file = input.files?.[0];
        if (!file) return;
        try {
          await uploadFile({
            file,
            resumeKey: fileKey(`${token}:${r.key}`, file),
            begin: () =>
              api(
                `${base}/uploads`,
                'POST',
                { requirement_key: r.key, name: file.name, size: file.size },
                h(),
              ),
            status: (id) => api(`${base}/uploads/${encodeURIComponent(id)}`, 'GET', undefined, h()),
            sign: (id, nums) =>
              api(
                `${base}/uploads/${encodeURIComponent(id)}/parts`,
                'POST',
                { part_numbers: nums },
                h(),
              ),
            complete: (id) =>
              api(`${base}/uploads/${encodeURIComponent(id)}/complete`, 'POST', {}, h()),
            onProgress: ({ sent, total }) => (bar.value = Math.round((sent / total) * 100)),
          });
          await render(await api(`${base}/submission`, 'GET', undefined, h()));
        } catch (e) {
          notice(e.message, true);
        }
      });
      row.append(input, bar);
    }
    reqs.append(row);
  }
  content().replaceChildren(
    intro(),
    reqs,
    panel(
      button(
        'Send files',
        async () => {
          try {
            await api(`${base}/submission/submit`, 'POST', {}, h());
            await render(await api(`${base}/submission`, 'GET', undefined, h()));
          } catch (e) {
            if (e.details?.missing)
              notice(
                `Still needed: ${e.details.missing.map((k) => info.requirements.find((r) => r.key === k)?.label || k).join(', ')}`,
                true,
              );
            else throw e;
          }
        },
        'primary',
      ),
    ),
  );
}

wireReport();
void open();
