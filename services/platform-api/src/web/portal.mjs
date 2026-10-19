import { BrowserDevice } from './device.mjs';
import { filesView } from './files.mjs';
const $ = (id) => document.getElementById(id);
const state = {
  token: '',
  principal: null,
  orgs: [],
  orgId: '',
  products: [],
  view: 'Licenses',
  version: 0,
};
const content = $('content');
let recoveryAvailable = false;
let passkeysAvailable = false;
const device = new BrowserDevice();
const node = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
};
const panel = (...children) => {
  const p = node('section', undefined, 'panel');
  p.append(...children);
  return p;
};
function notice(message = '', error = false) {
  $('notice').textContent = message;
  $('notice').className = error ? 'error' : '';
}
function errorMessage(e) {
  notice(e.message || 'The request could not be completed.', true);
}
async function api(path, method = 'GET', body) {
  const response = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(state.token ? { authorization: `Bearer ${state.token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    if (response.status === 401 && state.token) {
      state.token = '';
      state.principal = null;
      renderAuth();
    }
    const error = new Error(
      `${json?.message || 'Request failed'}${json?.request_id ? ` · Reference ${json.request_id}` : ''}`,
    );
    error.status = response.status;
    throw error;
  }
  return json;
}
function button(text, action, cls) {
  const b = node('button', text, cls);
  b.type = 'button';
  b.addEventListener('click', async () => {
    b.disabled = true;
    try {
      await action();
    } catch (e) {
      errorMessage(e);
    } finally {
      b.disabled = false;
    }
  });
  return b;
}
function title(text, description) {
  const h = node('div', undefined, 'title-row');
  const copy = node('div');
  copy.append(node('h1', text), node('p', description));
  h.append(copy);
  return h;
}
function fieldsForm(specs, submitText, action) {
  const form = node('form');
  const controls = {};
  for (const spec of specs) {
    const label = node('label', spec.label);
    let input;
    if (spec.options) {
      input = node('select');
      for (const [value, text] of spec.options) {
        const option = node('option', text);
        option.value = value;
        input.append(option);
      }
    } else if (spec.type === 'json') {
      input = node('textarea');
      input.value = spec.value ?? '{}';
    } else {
      input = node('input');
      input.type = spec.type || 'text';
      input.value = spec.value ?? '';
      if (spec.type === 'password') input.autocomplete = spec.autocomplete || 'current-password';
      else if (spec.type === 'email') input.autocomplete = 'email';
      if (spec.autocomplete) input.autocomplete = spec.autocomplete;
    }
    input.name = spec.name;
    input.setAttribute('aria-label', spec.label);
    input.required = !spec.optional;
    if (spec.min && spec.type !== 'number') input.minLength = spec.min;
    if (spec.type === 'number') input.min = spec.min ?? 0;
    label.append(input);
    form.append(label);
    controls[spec.name] = { input, spec };
  }
  const submit = node('button', submitText, 'primary');
  submit.type = 'submit';
  form.append(submit);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    submit.disabled = true;
    notice();
    try {
      const data = {};
      for (const [name, { input, spec }] of Object.entries(controls)) {
        if (!input.value && spec.optional) continue;
        data[name] =
          spec.type === 'number'
            ? Number(input.value)
            : spec.type === 'json'
              ? JSON.parse(input.value)
              : input.value;
      }
      await action(data, form);
    } catch (err) {
      errorMessage(err);
    } finally {
      submit.disabled = false;
    }
  });
  return form;
}
function showSecret(secret, heading = 'Save your license key', label = 'One-time license key') {
  const box = $('modal-content');
  box.replaceChildren(
    node('h2', heading),
    node(
      'p',
      'This key is shown once. Store it in your password manager. It is not saved in browser storage.',
    ),
  );
  const input = node('input');
  input.value = secret;
  input.readOnly = true;
  input.setAttribute('aria-label', label);
  box.append(input);
  $('modal').showModal();
  input.focus();
  input.select();
}
$('close-modal').addEventListener('click', () => {
  $('modal').close();
  $('modal-content').replaceChildren();
});
$('modal').addEventListener('close', () => $('modal-content').replaceChildren());
function renderAuth(register = false) {
  state.version++;
  $('navigation').replaceChildren();
  $('organization').replaceChildren();
  $('identity').textContent = '';
  $('signout').hidden = true;
  const card = panel(
    node('h1', register ? 'Create your account' : 'Welcome back'),
    node(
      'p',
      register
        ? 'Manage licenses and devices in your personal workspace.'
        : 'Sign in to your software workspace.',
    ),
  );
  card.classList.add('auth');
  card.append(
    fieldsForm(
      [
        { name: 'email', label: 'Email', type: 'email' },
        {
          name: 'password',
          label: 'Password',
          type: 'password',
          min: register ? 12 : 1,
          autocomplete: register ? 'new-password' : 'current-password',
        },
        ...(!register
          ? [
              {
                name: 'code',
                label: 'Authenticator or recovery code (if enabled)',
                optional: true,
                autocomplete: 'one-time-code',
              },
            ]
          : []),
      ],
      register ? 'Create account' : 'Sign in',
      async (data, form) => {
        if (register) await api('/v1/auth/register', 'POST', data);
        const result = await api('/v1/auth/login', 'POST', data);
        form.reset();
        state.token = result.token;
        await initialize();
      },
    ),
    button(register ? 'Already have an account? Sign in' : 'New here? Create an account', () =>
      renderAuth(!register),
    ),
  );
  if (!register && passkeysAvailable)
    card.append(
      button('Sign in with a passkey', async () => {
        const options = await api('/v1/auth/passkeys/login/begin', 'POST', {});
        const cred = await navigator.credentials.get({
          publicKey: {
            challenge: fromB64u(options.challenge),
            rpId: options.rpId,
            timeout: options.timeout,
            userVerification: 'required',
            allowCredentials: [],
          },
        });
        if (!cred) return;
        const r = cred.response;
        const result = await api('/v1/auth/passkeys/login/finish', 'POST', {
          credential: {
            id: cred.id,
            type: 'public-key',
            response: {
              clientDataJSON: toB64u(r.clientDataJSON),
              authenticatorData: toB64u(r.authenticatorData),
              signature: toB64u(r.signature),
              ...(r.userHandle ? { userHandle: toB64u(r.userHandle) } : {}),
            },
          },
        });
        state.token = result.token;
        await initialize();
      }),
    );
  if (!register && recoveryAvailable)
    card.append(button('Forgot password?', renderRecoveryRequest));
  content.replaceChildren(card);
  notice();
}
function renderRecoveryRequest() {
  notice();
  content.replaceChildren(
    panel(
      node('h1', 'Recover your account'),
      node('p', 'Enter your account email. Recovery links expire after 15 minutes.'),
      fieldsForm(
        [{ name: 'email', label: 'Account email', type: 'email' }],
        'Send recovery link',
        async (data, form) => {
          const result = await api('/v1/auth/password/request', 'POST', data);
          form.reset();
          notice(result.message);
        },
      ),
      button('Back to sign in', () => renderAuth()),
    ),
  );
}
async function startPortal() {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const reset = fragment.get('reset');
  const verify = fragment.get('verify');
  if (reset || verify) {
    state.token = '';
    state.principal = null;
    renderAuth();
    history.replaceState(null, '', '/');
  }
  try {
    const options = await api('/v1/auth/options');
    recoveryAvailable = options.email_recovery_configured;
    passkeysAvailable = !!options.passkeys_configured && !!window.PublicKeyCredential;
  } catch {
    recoveryAvailable = false;
  }
  if (reset) {
    content.replaceChildren(
      panel(
        node('h1', 'Choose a new password'),
        fieldsForm(
          [
            {
              name: 'password',
              label: 'New password',
              type: 'password',
              min: 12,
              autocomplete: 'new-password',
            },
          ],
          'Reset password',
          async (data, form) => {
            await api('/v1/auth/password/reset', 'POST', { token: reset, password: data.password });
            form.reset();
            renderAuth();
            notice(
              'Password reset. Existing sessions were signed out. Sign in with your new password.',
            );
          },
        ),
        button('Back to sign in', () => renderAuth()),
      ),
    );
    return;
  }
  renderAuth();
  if (verify) {
    try {
      await api('/v1/auth/email/verify', 'POST', { token: verify });
      notice('Email verified. Sign in to continue.');
    } catch (e) {
      errorMessage(e);
    }
  }
}
async function initialize() {
  state.principal = await api('/v1/auth/me');
  state.orgs = (await api('/v1/organizations')).items;
  state.products = (await api('/v1/catalog/products')).items;
  state.orgId = state.orgs[0]?.id || '';
  renderShell();
  await navigate('Licenses');
}
function renderShell() {
  const select = $('organization');
  select.replaceChildren();
  for (const org of state.orgs) {
    const o = node('option', `${org.name} · ${org.role}`);
    o.value = org.id;
    select.append(o);
  }
  select.value = state.orgId;
  $('identity').textContent =
    state.principal.platform_role === 'platform_admin' ? 'Platform operator' : 'Customer workspace';
  $('signout').hidden = false;
  const views = [
    'Licenses',
    'Files & links',
    'Devices',
    'Organization',
    'Catalog',
    'Device demo',
    'Account',
    'Security center',
  ];
  if (state.principal.platform_role === 'platform_admin') views.push('Operator console');
  $('navigation').replaceChildren(...views.map((view) => button(view, () => navigate(view))));
}
$('organization').addEventListener('change', async () => {
  state.orgId = $('organization').value;
  try {
    await navigate(state.view);
  } catch (e) {
    errorMessage(e);
  }
});
$('signout').addEventListener('click', async () => {
  try {
    await api('/v1/auth/logout', 'POST');
    state.token = '';
    state.principal = null;
    renderAuth();
  } catch (e) {
    errorMessage(e);
  }
});
const orgPath = () => `/v1/organizations/${encodeURIComponent(state.orgId)}`;
function empty(text) {
  return node('p', text, 'empty');
}
function badge(text) {
  return node('span', text, `badge ${['active', 'valid'].includes(text) ? '' : 'inactive'}`);
}
function table(columns, rows) {
  const wrap = node('div', undefined, 'table-wrap');
  const t = node('table');
  const head = node('thead');
  const tr = node('tr');
  columns.forEach((c) => tr.append(node('th', c)));
  head.append(tr);
  const body = node('tbody');
  for (const row of rows) {
    const r = node('tr');
    row.forEach((value, index) => {
      const td = node('td');
      td.dataset.label = columns[index];
      if (value instanceof Node) td.append(value);
      else td.textContent = String(value ?? '—');
      r.append(td);
    });
    body.append(r);
  }
  t.append(head, body);
  wrap.append(t);
  return wrap;
}
function details(object) {
  const dl = node('dl');
  for (const [key, value] of Object.entries(object)) {
    dl.append(
      node('dt', key.replaceAll('_', ' ')),
      node('dd', typeof value === 'object' ? JSON.stringify(value) : String(value ?? '—')),
    );
  }
  return dl;
}
const productName = (id) => state.products.find((p) => p.id === id)?.name || id;
async function navigate(view) {
  state.view = view;
  const version = ++state.version;
  notice();
  content.replaceChildren(node('div', 'Loading your workspace…', 'loading'));
  for (const n of $('navigation').children)
    n.setAttribute('aria-current', n.textContent === view ? 'page' : 'false');
  try {
    const page = await renderView(view);
    if (version === state.version && state.token) {
      content.replaceChildren(...page);
      document.title = `${view} · Rokela Bai Bureh Warrior`;
    }
  } catch (e) {
    if (version === state.version) {
      content.replaceChildren(
        panel(
          node('h1', view),
          empty('Could not load this view.'),
          button('Try again', () => navigate(view)),
        ),
      );
      errorMessage(e);
    }
  }
}
async function renderView(view) {
  if (view === 'Licenses') {
    const rows = (await api(`${orgPath()}/licenses`)).items;
    const section = panel(
      rows.length
        ? table(
            ['Product', 'License status', 'Plan', 'Devices', ''],
            rows.map((l) => [
              productName(l.product_id),
              badge(l.status),
              l.tier || l.plan_id,
              `${l.active_devices} / ${l.device_limit}`,
              button('View details', () => licenseDetail(l)),
            ]),
          )
        : empty('No licenses yet. Browse the catalog to start an available trial.'),
    );
    return [
      title('Licenses', 'Manage your software access, entitlements, and device activations.'),
      section,
    ];
  }
  if (view === 'Devices') {
    const licenses = (await api(`${orgPath()}/licenses`)).items;
    const rows = [];
    for (const l of licenses) {
      const acts = (await api(`${orgPath()}/licenses/${l.id}/activations`)).items;
      for (const a of acts) {
        rows.push([
          productName(l.product_id),
          node('span', a.device_id, 'mono'),
          badge(a.status),
          a.last_validated_at || 'Not yet validated',
          a.status === 'active'
            ? button(
                'Deactivate',
                async () => {
                  const until = a.last_lease_expires_at
                    ? new Date(a.last_lease_expires_at).toLocaleString()
                    : null;
                  if (
                    !confirm(
                      until
                        ? `Deactivate this device and free its slot? If it is offline it can keep working until ${until}, when its current lease expires.`
                        : 'Deactivate this device and free its slot?',
                    )
                  )
                    return;
                  await api(`${orgPath()}/activations/${a.id}/deactivate`, 'POST');
                  await navigate('Devices');
                  notice(
                    'Slot freed. To move the license, activate it on the new device.' +
                      (until ? ` The old device can work offline until ${until}.` : ''),
                  );
                },
                'danger',
              )
            : '—',
        ]);
      }
    }
    return [
      title('Devices', 'Review active installations and free a device slot when needed.'),
      panel(
        rows.length
          ? table(['Product', 'Device', 'Status', 'Last validation', ''], rows)
          : empty('No device activations in this workspace.'),
      ),
    ];
  }
  if (view === 'Organization') {
    const org = await api(orgPath());
    const members = (await api(`${orgPath()}/members`)).items;
    const sections = [
      title('Organization', 'Manage your workspace and its membership.'),
      panel(
        node('h2', org.name),
        details({ organization_id: org.id, kind: org.kind, role: org.role }),
      ),
      panel(
        node('h2', 'Members'),
        table(
          ['User', 'Role'],
          members.map((m) => [m.user_id, m.role]),
        ),
      ),
    ];
    if (['owner', 'admin'].includes(org.role))
      sections.push(
        panel(
          node('h2', 'Add a member'),
          fieldsForm(
            [
              { name: 'email', label: 'Existing account email', type: 'email' },
              {
                name: 'role',
                label: 'Role',
                options: [
                  ['member', 'Member'],
                  ['admin', 'Admin'],
                  ['owner', 'Owner'],
                ],
              },
            ],
            'Add member',
            async (data) => {
              await api(`${orgPath()}/members`, 'POST', data);
              await navigate('Organization');
            },
          ),
        ),
      );
    sections.push(
      panel(
        node('h2', 'Create a team workspace'),
        fieldsForm(
          [{ name: 'name', label: 'Workspace name' }],
          'Create workspace',
          async (data) => {
            const created = await api('/v1/organizations', 'POST', data);
            state.orgs = (await api('/v1/organizations')).items;
            state.orgId = created.id;
            renderShell();
            await navigate('Organization');
          },
        ),
      ),
    );
    return sections;
  }
  if (view === 'Catalog') {
    return [
      title(
        'Software catalog',
        'Explore available products and plans. Trial eligibility is checked by the server.',
      ),
      ...(await Promise.all(
        state.products.map(async (p) => {
          const plans = (await api(`/v1/catalog/products/${p.id}/plans`)).items;
          const card = panel(
            node('h2', p.name),
            node('p', p.code),
            table(
              ['Plan', 'Tier', 'Devices', 'Capabilities'],
              plans.map((plan) => [
                plan.code,
                plan.tier,
                plan.device_limit,
                plan.capabilities.join(', ') || '—',
              ]),
            ),
          );
          if (plans.some((plan) => plan.tier === 'trial'))
            card.append(
              button(
                'Start trial',
                async () => {
                  const grant = await api(`${orgPath()}/trials`, 'POST', { product_id: p.id });
                  showSecret(grant.license_key, 'Your trial license key');
                  notice('Trial created. You can now activate a device.');
                },
                'primary',
              ),
            );
          return card;
        }),
      )),
      ...(state.products.length ? [] : [panel(empty('No products published yet.'))]),
    ];
  }
  if (view === 'Files & links')
    return filesView({
      api,
      node,
      panel,
      button,
      title,
      table,
      badge,
      empty,
      details,
      fieldsForm,
      notice,
      errorMessage,
      content,
      orgPath,
      orgId: () => state.orgId,
      modal: (...children) => {
        $('modal-content').replaceChildren(...children);
        $('modal').showModal();
      },
      // Authorized fetch of a small binary resource (QR codes) for display and download.
      blob: async (path) => {
        const r = await fetch(path, { headers: { authorization: `Bearer ${state.token}` } });
        if (!r.ok) throw new Error('Could not load the file.');
        return r.blob();
      },
    });
  if (view === 'Device demo') return deviceView();
  if (view === 'Security center') return securityCenterView();
  if (view === 'Account')
    return [
      title(
        'Account',
        'Your session is kept in memory and ends when you reload or close this page.',
      ),
      panel(
        details({
          email: state.principal.email,
          user_id: state.principal.user_id,
          email_verification: state.principal.email_verified ? 'Verified' : 'Not verified',
          authenticator_mfa: state.principal.mfa_enabled ? 'Enabled' : 'Not enabled',
        }),
        ...(state.principal.recovery_configured && !state.principal.email_verified
          ? [
              button('Send verification email', async () => {
                const result = await api('/v1/auth/email/request', 'POST', {});
                notice(result.message);
              }),
            ]
          : []),
        node(
          'p',
          'Your device-demo identity is separate from your account session. Signing out does not revoke existing offline device leases.',
        ),
        button('Sign out', () => $('signout').click()),
      ),
      mfaPanel(),
      await passkeyPanel(),
    ];
  if (view === 'Operator console') return operatorView();
  return [];
}
async function securityCenterView() {
  const sc = await api('/v1/security-center');
  const yes = (v) => (v ? 'Yes' : 'No');
  return [
    title(
      'Security center',
      'How your account is protected, what your roles allow, your devices, and what we collect.',
    ),
    ...(sc.recommendations.length
      ? [panel(node('h2', 'Recommended'), ...sc.recommendations.map((r) => node('p', r)))]
      : []),
    panel(
      node('h2', 'Your account'),
      details({
        email: sc.account.email,
        email_verified: yes(sc.account.email_verified),
        authenticator_app: yes(sc.account.authenticator_enabled),
        passkeys: sc.account.passkeys,
        platform_operator: yes(sc.account.operator),
      }),
    ),
    ...sc.organizations.map((o) =>
      panel(
        node('h2', `${o.name} — ${o.role}`),
        table(
          ['You may', 'Permission'],
          o.permissions.map((x) => [x.description, node('span', x.permission, 'mono')]),
        ),
      ),
    ),
    panel(
      node('h2', 'Your devices'),
      sc.devices.length
        ? table(
            ['Device', 'Trust', 'Hardware evidence', 'Works offline until'],
            sc.devices.map((d) => [
              node('span', d.device_id, 'mono'),
              badge(d.posture),
              d.attestation === 'unknown' ? 'None verified' : d.attestation,
              d.offline_lease_valid_until
                ? new Date(d.offline_lease_valid_until).toLocaleString()
                : '—',
            ]),
          )
        : empty('You have not activated any devices.'),
    ),
    panel(
      node('h2', 'What we collect'),
      table(
        ['Category', 'Contents', 'Why', 'Kept'],
        sc.data_categories.map((d) => [d.category, d.contents, d.purpose, d.retention]),
      ),
    ),
  ];
}

// WebAuthn binary fields travel as base64url; nothing about a passkey is kept in browser storage.
const toB64u = (buffer) =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
const fromB64u = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

async function passkeyPanel() {
  const card = panel(node('h2', 'Passkeys'));
  if (!passkeysAvailable) {
    card.append(node('p', 'Passkeys are not available on this deployment or in this browser.'));
    return card;
  }
  const keys = (await api('/v1/auth/passkeys')).items;
  card.append(
    node(
      'p',
      'Sign in with your fingerprint, face or device PIN instead of a password. Passkeys cannot be phished: they only work on this site.',
    ),
    keys.length
      ? table(
          ['Name', 'Added', 'Last used', ''],
          keys.map((k) => [
            k.name,
            new Date(k.created_at).toLocaleDateString(),
            k.last_used_at ? new Date(k.last_used_at).toLocaleString() : 'Never',
            button('Remove', async () => {
              const password = prompt(`Enter your password to remove "${k.name}"`);
              if (!password) return;
              await api(`/v1/auth/passkeys/${encodeURIComponent(k.id)}/delete`, 'POST', {
                password,
              });
              await navigate('Account');
              notice('Passkey removed.');
            }),
          ]),
        )
      : empty('No passkeys yet.'),
    fieldsForm(
      [
        { name: 'name', label: 'Name for this passkey (for example "Work laptop")', min: 1 },
        { name: 'password', label: 'Current password', type: 'password' },
      ],
      'Add a passkey',
      async (data, form) => {
        const options = await api('/v1/auth/passkeys/register/begin', 'POST', {
          password: data.password,
        });
        const cred = await navigator.credentials.create({
          publicKey: {
            ...options,
            challenge: fromB64u(options.challenge),
            user: { ...options.user, id: fromB64u(options.user.id) },
            excludeCredentials: options.excludeCredentials.map((c) => ({
              ...c,
              id: fromB64u(c.id),
            })),
          },
        });
        if (!cred) return;
        await api('/v1/auth/passkeys/register/finish', 'POST', {
          name: data.name,
          credential: {
            id: cred.id,
            type: 'public-key',
            response: {
              clientDataJSON: toB64u(cred.response.clientDataJSON),
              attestationObject: toB64u(cred.response.attestationObject),
            },
          },
        });
        form.reset();
        await navigate('Account');
        notice('Passkey added. You can now sign in with it.');
      },
    ),
  );
  return card;
}

function mfaPanel() {
  if (!state.principal.mfa_configured)
    return panel(
      node('h2', 'Authenticator protection'),
      node('p', 'Authenticator setup is not configured on this deployment.'),
    );
  const card = panel(node('h2', 'Authenticator protection'));
  if (
    state.principal.operator_mfa_required &&
    state.principal.platform_role === 'platform_admin' &&
    !state.principal.mfa_enabled
  )
    card.append(node('p', 'Enroll an authenticator before using operator administration.'));
  if (state.principal.mfa_enabled) {
    card.append(
      node(
        'p',
        'Disabling protection signs out every session. Your password and an unused authenticator or recovery code are required.',
      ),
      fieldsForm(
        [
          { name: 'password', label: 'Current password', type: 'password' },
          { name: 'code', label: 'Authenticator or recovery code', autocomplete: 'one-time-code' },
          { name: 'reason', label: 'Reason for disabling', min: 3 },
        ],
        'Disable authenticator',
        async (data, form) => {
          await api('/v1/auth/mfa/disable', 'POST', data);
          form.reset();
          state.token = '';
          state.principal = null;
          renderAuth();
          notice('Authenticator disabled. All sessions signed out.');
        },
      ),
    );
    return card;
  }
  card.append(
    node(
      'p',
      'Add a six-digit authenticator such as Microsoft Authenticator, Google Authenticator or a compatible password manager. Keep recovery codes safely offline.',
    ),
    fieldsForm(
      [{ name: 'password', label: 'Current password', type: 'password' }],
      'Set up authenticator',
      async (data, form) => {
        const setup = await api('/v1/auth/mfa/begin', 'POST', data);
        form.reset();
        // Setup secret exists only in this view. Navigation removes it; nothing goes to storage or a QR service.
        const secret = node('input');
        secret.readOnly = true;
        secret.value = setup.setup_key;
        secret.setAttribute('aria-label', 'Authenticator setup key');
        card.replaceChildren(
          node('h2', 'Confirm your authenticator'),
          node(
            'p',
            'Add a manual time-based entry named Rokela Bai Bureh Warrior in your authenticator. Use this setup key with six digits and a 30-second period. Setup expires in ten minutes.',
          ),
          secret,
          fieldsForm(
            [
              { name: 'password', label: 'Current password', type: 'password' },
              {
                name: 'code',
                label: 'Six-digit authenticator code',
                autocomplete: 'one-time-code',
              },
            ],
            'Enable authenticator',
            async (confirm, confirmForm) => {
              const result = await api('/v1/auth/mfa/confirm', 'POST', confirm);
              confirmForm.reset();
              secret.value = '';
              state.token = '';
              state.principal = null;
              renderAuth();
              showSecret(
                result.recovery_codes.join(' '),
                'Save your single-use recovery codes',
                'One-time recovery codes',
              );
              notice(
                'Authenticator enabled. All sessions signed out. Use a new code or a recovery code to sign in.',
              );
            },
          ),
        );
      },
    ),
  );
  return card;
}
async function billingPanel(l, license) {
  if (!['admin', 'owner'].includes(state.orgs.find((o) => o.id === state.orgId)?.role)) return null;
  const configured = await api('/v1/billing/catalog');
  if (!configured.plan_ids.length || !license.subscription_id || license.state !== 'active')
    return null;
  const card = panel(node('h2', 'Subscription checkout'));
  const renderCheckout = (checkout) => {
    card.replaceChildren(node('h2', 'Subscription checkout'), details(checkout));
    if (checkout.status === 'ready' && checkout.checkout_url) {
      const url = new URL(checkout.checkout_url);
      if (url.protocol !== 'https:') throw new Error('Invalid payment link');
      const link = node('a', 'Continue to secure payment');
      link.href = url.href;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      card.append(link);
    } else if (['submitting', 'uncertain'].includes(checkout.status)) {
      card.append(
        node(
          'p',
          'Checkout is awaiting confirmation. Contact support if this persists; submitting again will not create another payment.',
        ),
      );
    } else {
      card.append(node('p', 'Payment processed. Current subscription details appear above.'));
    }
    card.append(
      button('Refresh checkout status', async () =>
        renderCheckout(await api(`${orgPath()}/licenses/${l.id}/checkout`)),
      ),
    );
  };
  try {
    renderCheckout(await api(`${orgPath()}/licenses/${l.id}/checkout`));
    return card;
  } catch (error) {
    if (error.status !== 404) throw error;
  }

  const plans = (
    await api(`/v1/catalog/products/${encodeURIComponent(l.product_id)}/plans`)
  ).items.filter((p) => configured.plan_ids.includes(p.id));
  if (!plans.length) return null;
  // Keep one operation ID for all retries of this form. Reload reads the durable existing intent first.
  const operationId = crypto.randomUUID();
  card.append(
    node(
      'p',
      'Choose a plan and review its price and recurring terms on the payment page before paying.',
    ),
    fieldsForm(
      [
        {
          name: 'plan_id',
          label: 'Subscription plan',
          options: plans.map((p) => [p.id, `${p.code} · ${p.tier}`]),
        },
      ],
      'Create checkout',
      async (data) =>
        renderCheckout(
          await api(`${orgPath()}/licenses/${l.id}/checkout`, 'POST', {
            plan_id: data.plan_id,
            idempotency_key: operationId,
          }),
        ),
    ),
  );
  return card;
}
async function licenseDetail(l) {
  const [license, ent, activations, usage] = await Promise.all([
    api(`${orgPath()}/licenses/${l.id}`),
    api(
      `/v1/entitlements?org_id=${encodeURIComponent(state.orgId)}&license_id=${encodeURIComponent(l.id)}`,
    ),
    api(`${orgPath()}/licenses/${l.id}/activations`),
    api(`${orgPath()}/licenses/${l.id}/usage`),
  ]);
  content.replaceChildren(
    title(productName(l.product_id), 'License details and currently resolved entitlements.'),
    panel(
      button('← All licenses', () => navigate('Licenses')),
      details(license),
    ),
    panel(node('h2', 'Entitlements'), details(ent)),
    panel(
      node('h2', 'Monthly usage'),
      node(
        'p',
        `Period ${usage.period} · Resets ${new Date(usage.resets_at).toLocaleDateString(undefined, { timeZone: 'UTC' })} (UTC). Allowances are shared by users of this license.`,
      ),
      ...(usage.status !== 'valid'
        ? [node('p', 'This license is currently unavailable for consumption.')]
        : []),
      ...(usage.items.length
        ? [
            table(
              ['Allowance', 'Used', 'Limit', 'Remaining'],
              usage.items.map((item) => [
                item.entitlement
                  .replace(/_monthly$/, '')
                  .split('_')
                  .map((word, index) =>
                    word === 'ocr'
                      ? 'OCR'
                      : word === 'ai'
                        ? 'AI'
                        : index === 0
                          ? word[0].toUpperCase() + word.slice(1)
                          : word,
                  )
                  .join(' '),
                item.used,
                item.limit,
                item.remaining,
              ]),
            ),
          ]
        : [empty('No monthly allowances are configured for this license.')]),
    ),
    panel(
      node('h2', 'Activations'),
      table(
        ['Installation', 'Status', 'Last validation'],
        activations.items.map((a) => [a.installation_id, badge(a.status), a.last_validated_at]),
      ),
    ),
  );
  const seats = await seatPanel(l);
  if (seats) content.append(seats);
  const billing = await billingPanel(l, license);
  if (billing) content.append(billing);
}

/** Named-user seats (ADR-025): shown only for seat-based licenses; admins assign and remove them. */
async function seatPanel(l) {
  const seats = await api(`${orgPath()}/licenses/${l.id}/seats`);
  if (seats.limit === null) return undefined;
  const base = `${orgPath()}/licenses/${l.id}/seats`;
  const members = await api(`${orgPath()}/members`).catch(() => ({ items: [] }));
  const label = (userId) => members.items.find((m) => m.user_id === userId)?.email || userId;
  const card = panel(
    node('h2', `Seats (${seats.used} of ${seats.limit} used)`),
    node(
      'p',
      'Only people with a seat can activate this license. Removing a seat signs out their devices; an offline device keeps working until its current lease expires.',
    ),
    seats.items.length
      ? table(
          ['Person', 'Assigned', ''],
          seats.items.map((s) => [
            label(s.user_id),
            new Date(s.assigned_at).toLocaleDateString(),
            button(
              'Remove seat',
              async () => {
                if (!confirm(`Remove ${label(s.user_id)}'s seat and sign out their devices?`))
                  return;
                const r = await api(`${base}/${s.user_id}/unassign`, 'POST', {});
                await licenseDetail(l);
                notice(
                  `Seat removed; ${r.activations_deactivated} device(s) signed out.` +
                    (r.offline_leases_valid_until
                      ? ` Offline devices can keep working until ${new Date(r.offline_leases_valid_until).toLocaleString()}.`
                      : ''),
                );
              },
              'danger',
            ),
          ]),
        )
      : empty('No seats assigned yet.'),
  );
  const free = members.items.filter((m) => !seats.items.some((s) => s.user_id === m.user_id));
  if (free.length && seats.used < seats.limit) {
    const select = node('select');
    select.setAttribute('aria-label', 'Person to give a seat');
    for (const m of free) {
      const o = node('option', m.email || m.user_id);
      o.value = m.user_id;
      select.append(o);
    }
    card.append(
      select,
      button('Assign seat', async () => {
        await api(base, 'POST', { user_id: select.value });
        await licenseDetail(l);
        notice('Seat assigned.');
      }),
    );
  }
  return card;
}
async function deviceView() {
  const status = await device.summary();
  const statusBox = panel(node('h2', 'This browser installation'), details(status));
  const output = node('div');
  const run = async (action) => {
    const value = await action();
    statusBox.replaceChildren(
      node('h2', 'This browser installation'),
      details(await device.summary()),
    );
    output.replaceChildren(node('pre', JSON.stringify(value, null, 2)));
  };
  return [
    title(
      'Device demo',
      'Exercise real device activation and signed offline verification. This browser key is software-backed, not hardware-attested.',
    ),
    statusBox,
    panel(
      fieldsForm(
        [
          { name: 'license_key', label: 'License key', type: 'password', autocomplete: 'off' },
          {
            name: 'product_code',
            label: 'Product code',
            options: state.products.map((p) => [p.code, p.name]),
          },
        ],
        'Activate this browser',
        async (data, form) => {
          await run(() => device.activate(data.license_key, data.product_code, api));
          form.reset();
        },
      ),
    ),
    panel(
      node('h2', 'Device actions'),
      node(
        'p',
        'Offline verification uses the public keys cached at activation. Reloading retains this demo device identity.',
      ),
      node('div', undefined, 'actions'),
      output,
    ),
    panel(
      ...['Validate online', 'Refresh lease', 'Verify offline', 'Deactivate'].map((label, i) =>
        button(label, () =>
          run(() =>
            [
              () => device.call('validate', api),
              () => device.call('refresh', api),
              () => device.offline(),
              () => device.call('deactivate', api),
            ][i](),
          ),
        ),
      ),
    ),
  ];
}
const reason = { name: 'reason', label: 'Reason (required for the audit log)', min: 3 };
const ids = (name, label) => ({ name, label });
async function operatorView() {
  if (state.principal.platform_role !== 'platform_admin')
    throw new Error('Operator permission required');
  const sections = [
    title(
      'Operator console',
      'Provision software access and inspect audit evidence. Every mutation requires a reason.',
    ),
  ];
  const forms = [
    [
      'Create product',
      [ids('code', 'Product code'), ids('name', 'Product name'), reason],
      '/v1/admin/products',
      'POST',
    ],
    [
      'Create plan',
      [
        ids('product_id', 'Product ID'),
        ids('code', 'Plan code'),
        {
          name: 'tier',
          label: 'Tier',
          options: ['trial', 'standard', 'professional', 'business', 'enterprise'].map((x) => [
            x,
            x,
          ]),
        },
        { name: 'entitlements', label: 'Entitlements (JSON object)', type: 'json' },
        { name: 'capabilities', label: 'Capabilities (JSON array)', type: 'json', value: '[]' },
        { name: 'device_limit', label: 'Device limit', type: 'number', value: '3' },
        reason,
      ],
      (d) => `/v1/admin/products/${encodeURIComponent(d.product_id)}/plans`,
      'POST',
    ],
    [
      'Update plan',
      [
        ids('plan_id', 'Plan ID'),
        { name: 'entitlements', label: 'Entitlements (JSON object)', type: 'json' },
        { name: 'capabilities', label: 'Capabilities (JSON array)', type: 'json', value: '[]' },
        { name: 'device_limit', label: 'Device limit', type: 'number', value: '3' },
        reason,
      ],
      (d) => `/v1/admin/plans/${encodeURIComponent(d.plan_id)}`,
      'PATCH',
    ],
    [
      'Create subscription',
      [
        ids('org_id', 'Organization ID'),
        ids('plan_id', 'Plan ID'),
        {
          name: 'status',
          label: 'Status',
          options: ['active', 'trialing', 'past_due', 'suspended', 'canceled', 'expired'].map(
            (x) => [x, x],
          ),
        },
        { name: 'current_period_end', label: 'Period end (ISO date/time)', optional: true },
        reason,
      ],
      (d) => `/v1/admin/organizations/${encodeURIComponent(d.org_id)}/subscriptions`,
      'POST',
    ],
    [
      'Update subscription',
      [
        ids('org_id', 'Organization ID'),
        ids('subscription_id', 'Subscription ID'),
        ids('plan_id', 'Plan ID'),
        {
          name: 'status',
          label: 'Status',
          options: ['active', 'trialing', 'past_due', 'suspended', 'canceled', 'expired'].map(
            (x) => [x, x],
          ),
        },
        { name: 'current_period_end', label: 'Period end (ISO date/time)', optional: true },
        reason,
      ],
      (d) =>
        `/v1/admin/organizations/${encodeURIComponent(d.org_id)}/subscriptions/${encodeURIComponent(d.subscription_id)}`,
      'PATCH',
    ],
    [
      'Reconcile uncertain checkout',
      [
        ids('org_id', 'Organization ID'),
        ids('license_id', 'License ID'),
        ids('transaction_id', 'Paddle transaction ID'),
        reason,
      ],
      (d) =>
        `/v1/admin/organizations/${encodeURIComponent(d.org_id)}/licenses/${encodeURIComponent(d.license_id)}/checkout/reconcile`,
      'POST',
    ],
    [
      'Issue license',
      [
        ids('org_id', 'Organization ID'),
        ids('product_id', 'Product ID'),
        ids('plan_id', 'Plan ID'),
        {
          name: 'kind',
          label: 'Kind',
          options: ['subscription', 'trial', 'perpetual', 'canary'].map((x) => [x, x]),
        },
        { name: 'subscription_id', label: 'Subscription ID', optional: true },
        { name: 'expires_at', label: 'Expiry (ISO date/time)', optional: true },
        reason,
      ],
      (d) => `/v1/admin/organizations/${encodeURIComponent(d.org_id)}/licenses`,
      'POST',
    ],
  ];
  for (const [heading, fields, path, method] of forms) {
    for (const field of fields) {
      if (field.name === 'device_limit') {
        field.min = -1;
        field.label = 'Device limit (-1 = unlimited)';
      }
      const leaveUnchanged =
        (heading === 'Update plan' &&
          ['entitlements', 'capabilities', 'device_limit'].includes(field.name)) ||
        (heading === 'Update subscription' && ['plan_id', 'status'].includes(field.name));
      if (leaveUnchanged) {
        field.optional = true;
        field.value = '';
        if (field.options) field.options.unshift(['', 'Leave unchanged']);
      }
    }
    if (heading === 'Create subscription')
      fields.splice(fields.length - 1, 0, {
        name: 'trial_end',
        label: 'Trial end (ISO date/time)',
        optional: true,
      });
    const result = node('div');
    sections.push(
      panel(
        node('h2', heading),
        fieldsForm(fields, heading, async (data, form) => {
          const url = typeof path === 'function' ? path(data) : path;
          const body = { ...data };
          for (const key of ['org_id', 'product_id', 'plan_id', 'subscription_id']) {
            if (
              (heading === 'Create plan' && key === 'product_id') ||
              (heading === 'Update plan' && key === 'plan_id') ||
              key === 'org_id' ||
              (heading === 'Update subscription' && key === 'subscription_id')
            )
              delete body[key];
          }
          const value = await api(url, method, body);
          if (value?.license_key) {
            showSecret(value.license_key);
            result.replaceChildren(node('pre', JSON.stringify(value.license, null, 2)));
          } else result.replaceChildren(node('pre', JSON.stringify(value, null, 2)));
          form.reset();
          state.products = (await api('/v1/catalog/products')).items;
          notice(`${heading} completed.`);
        }),
        result,
      ),
    );
  }
  const stateResult = node('div');
  sections.push(
    panel(
      node('h2', 'Change license state'),
      fieldsForm(
        [
          ids('org_id', 'Organization ID'),
          ids('license_id', 'License ID'),
          {
            name: 'action',
            label: 'Action',
            options: ['suspend', 'reinstate', 'revoke'].map((x) => [x, x]),
          },
          reason,
        ],
        'Apply state change',
        async (d) => {
          if (d.action === 'revoke' && !confirm('Revoke this license permanently?')) return;
          const value = await api(
            `/v1/admin/organizations/${encodeURIComponent(d.org_id)}/licenses/${encodeURIComponent(d.license_id)}/${d.action}`,
            'POST',
            { reason: d.reason },
          );
          stateResult.replaceChildren(node('pre', JSON.stringify(value, null, 2)));
        },
      ),
      stateResult,
    ),
  );
  const report = node('div');
  sections.push(
    panel(
      node('h2', 'Audit and operations'),
      node('div', undefined, 'actions'),
      button('Read latest audit events', async () =>
        report.replaceChildren(
          node('pre', JSON.stringify(await api('/v1/admin/audit?limit=100'), null, 2)),
        ),
      ),
      button('Verify audit chains', async () =>
        report.replaceChildren(
          node('pre', JSON.stringify(await api('/v1/admin/audit/verify'), null, 2)),
        ),
      ),
      button('View runtime metrics', async () =>
        report.replaceChildren(
          node('pre', JSON.stringify(await api('/v1/admin/metrics'), null, 2)),
        ),
      ),
      button('View audit anchors', async () =>
        report.replaceChildren(
          node('pre', JSON.stringify(await api('/v1/admin/audit/anchors'), null, 2)),
        ),
      ),
      fieldsForm([reason], 'Publish audit anchor', async (data) =>
        report.replaceChildren(
          node('pre', JSON.stringify(await api('/v1/admin/audit/anchors', 'POST', data), null, 2)),
        ),
      ),
      report,
    ),
  );
  const lookup = node('div');
  sections.push(
    panel(
      node('h2', 'Inspect organization licenses'),
      fieldsForm(
        [
          ids('org_id', 'Organization ID'),
          {
            name: 'license_id',
            label: 'License ID (optional, to inspect activations)',
            optional: true,
          },
        ],
        'Load records',
        async (data) => {
          const path = `/v1/admin/organizations/${encodeURIComponent(data.org_id)}/licenses${data.license_id ? `/${encodeURIComponent(data.license_id)}/activations` : ''}`;
          lookup.replaceChildren(node('pre', JSON.stringify(await api(path), null, 2)));
        },
      ),
      lookup,
    ),
  );
  const witness = node('div');
  sections.push(
    panel(
      node('h2', 'Check witness manifest'),
      fieldsForm(
        [{ name: 'manifest', label: 'Witness manifest (JSON)', type: 'json' }],
        'Check manifest',
        async (data) =>
          witness.replaceChildren(
            node(
              'pre',
              JSON.stringify(await api('/v1/admin/audit/anchors/check', 'POST', data), null, 2),
            ),
          ),
      ),
      witness,
    ),
  );
  const picker = node('select');
  picker.setAttribute('aria-label', 'Operator action');
  const operations = sections.slice(1);
  operations.forEach((section, index) => {
    const option = node('option', section.querySelector('h2').textContent);
    option.value = String(index);
    picker.append(option);
    section.hidden = index !== 0;
  });
  picker.addEventListener('change', () =>
    operations.forEach((section, index) => {
      section.hidden = String(index) !== picker.value;
    }),
  );
  const label = node('label', 'Choose an operation');
  label.append(picker);
  sections.splice(1, 0, panel(label));
  return sections;
}
globalThis.addEventListener('hashchange', () => void startPortal());
void startPortal();
