// Shared helpers for the public share, upload-request and short-link pages. These pages hold an optional sign-in
// session in memory only (lost on reload) and never store tokens, passwords or grants in browser storage.
export const $ = (id) => document.getElementById(id);
export const content = () => $('content');
export const state = { session: '' };

export const node = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
};
export const panel = (...children) => {
  const p = node('section', undefined, 'panel');
  p.append(...children);
  return p;
};
export function notice(message = '', error = false) {
  $('notice').textContent = message;
  $('notice').className = error ? 'error' : '';
}

export async function api(path, method = 'GET', body, headers = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(state.session ? { authorization: `Bearer ${state.session}` } : {}),
      ...headers,
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    const e = new Error(json?.message || 'The request could not be completed.');
    e.status = res.status;
    e.code = json?.code;
    e.details = json?.details;
    throw e;
  }
  return json;
}

export function button(text, action, cls) {
  const b = node('button', text, cls);
  b.type = 'button';
  b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      await action();
    } catch (e) {
      notice(e.message, true);
    } finally {
      b.disabled = false;
    }
  });
  return b;
}

/** A small form; resolves the submitted values to `action`. */
export function form(fields, submitText, action) {
  const f = node('form');
  const inputs = {};
  for (const spec of fields) {
    const label = node('label', spec.label);
    const input = node(spec.multiline ? 'textarea' : 'input');
    if (!spec.multiline) input.type = spec.type || 'text';
    input.name = spec.name;
    input.required = !spec.optional;
    if (spec.autocomplete) input.autocomplete = spec.autocomplete;
    label.append(input);
    f.append(label);
    inputs[spec.name] = input;
  }
  const submit = node('button', submitText, 'primary');
  submit.type = 'submit';
  f.append(submit);
  f.addEventListener('submit', async (e) => {
    e.preventDefault();
    submit.disabled = true;
    notice();
    try {
      await action(Object.fromEntries(Object.entries(inputs).map(([k, i]) => [k, i.value])));
    } catch (err) {
      notice(err.message, true);
    } finally {
      submit.disabled = false;
    }
  });
  return f;
}

/** In-page sign-in for restricted links and reviews (session kept in memory only). */
export function signIn(onDone) {
  return panel(
    node('h1', 'Sign in to continue'),
    node(
      'p',
      'This link is restricted to specific recipients. Sign in with the account the sender invited.',
    ),
    form(
      [
        { name: 'email', label: 'Email', type: 'email', autocomplete: 'email' },
        { name: 'password', label: 'Password', type: 'password', autocomplete: 'current-password' },
        {
          name: 'code',
          label: 'Authenticator code (if enabled)',
          optional: true,
          autocomplete: 'one-time-code',
        },
      ],
      'Sign in',
      async (v) => {
        const r = await api('/v1/auth/login', 'POST', {
          email: v.email,
          password: v.password,
          ...(v.code ? { code: v.code } : {}),
        });
        state.session = r.token;
        await onDone();
      },
    ),
  );
}

export function brand(b) {
  if (!b) return node('span');
  const h = node('p', b.display_name, 'brand-name');
  h.style.borderColor = b.accent_color;
  return h;
}

export function reportAbuse() {
  const page = location.href;
  content().replaceChildren(
    panel(
      node('h1', 'Report abuse'),
      node(
        'p',
        'Tell us about phishing, malware or spam shared through this link. Reports are reviewed by the platform team.',
      ),
      form(
        [
          { name: 'category', label: 'Category: phishing, malware, spam or other' },
          { name: 'details', label: 'What is wrong?', optional: true, multiline: true },
          {
            name: 'email',
            label: 'Your email (optional, for follow-up)',
            type: 'email',
            optional: true,
            autocomplete: 'email',
          },
        ],
        'Send report',
        async (v) => {
          const category = ['phishing', 'malware', 'spam'].includes(v.category.trim().toLowerCase())
            ? v.category.trim().toLowerCase()
            : 'other';
          await api('/v1/public/abuse-reports', 'POST', {
            reference: page.split('#')[0],
            category,
            ...(v.details ? { details: v.details } : {}),
            ...(v.email ? { email: v.email } : {}),
          });
          content().replaceChildren(
            panel(node('h1', 'Thank you'), node('p', 'Your report was received.')),
          );
        },
      ),
    ),
  );
}

export const fmtBytes = (n) => {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 && i ? 1 : 0)} ${u[i]}`;
};

export function wireReport() {
  $('report-link').addEventListener('click', (e) => {
    e.preventDefault();
    reportAbuse();
  });
}
