import { BrowserDevice } from './device.mjs';
import { filesView } from './files.mjs';
import { operationsView } from './operations.mjs';
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
const mobileLayout = window.matchMedia('(max-width: 760px)');
function closeNavigation(restoreFocus = false) {
  $('shell').classList.remove('navigation-open');
  $('menu-toggle').setAttribute('aria-expanded', 'false');
  if (restoreFocus && mobileLayout.matches) $('menu-toggle').focus();
}
$('menu-toggle').addEventListener('click', () => {
  const expanded = $('shell').classList.toggle('navigation-open');
  $('menu-toggle').setAttribute('aria-expanded', String(expanded));
});
mobileLayout.addEventListener('change', () => {
  // Hiding the desktop rail can blur its link before matchMedia delivers this event.
  const focusLost = document.activeElement === document.body;
  closeNavigation(
    mobileLayout.matches && (focusLost || $('navigation').contains(document.activeElement)),
  );
});
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && $('shell').classList.contains('navigation-open')) {
    closeNavigation(true);
  }
});
const navigationIcons = {
  Licenses: 'M6 3h9l4 4v14H6z M14 3v5h5 M9 12h7 M9 16h5',
  Applications: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  'Files & links':
    'M9 15l6-6 M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0 M16 8l1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0',
  Devices: 'M3 4h18v13H3z M8 21h8 M12 17v4',
  Organization:
    'M8 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8 M2 21v-3a6 6 0 0 1 12 0v3 M17 4a4 4 0 0 1 0 8 M17 15a5 5 0 0 1 5 5',
  Catalog: 'M3 7h18v14H3z M8 7V3h8v4 M3 12h18 M10 12v3h4v-3',
  'Device demo': 'M3 4h18v13H3z M8 21h8 M12 17v4 M9 8l-2 2 2 2 M15 8l2 2-2 2',
  Account: 'M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10 M3 22a9 9 0 0 1 18 0z',
  'Security center': 'M12 2l9 4v6c0 5-5 8-9 10-4-2-9-5-9-10V6z M8 12l3 3 5-6',
  'Operator console': 'M4 5l6 6-6 6 M12 19h8',
};
function navigationButton(view) {
  const item = button(view, async () => {
    closeNavigation();
    await navigate(view);
    if (mobileLayout.matches) content.focus();
  });
  const icon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  icon.setAttribute('viewBox', '0 0 24 24');
  icon.setAttribute('aria-hidden', 'true');
  icon.setAttribute('focusable', 'false');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', navigationIcons[view]);
  icon.append(path);
  item.prepend(icon);
  return item;
}

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
  const token = state.token;
  const response = await fetch(path, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const json = response.status === 204 ? null : await response.json();
  if (!response.ok) {
    if (response.status === 401 && token && state.token === token) {
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
      input.multiple = spec.type === 'multiselect';
      for (const [value, text] of spec.options) {
        const option = node('option', text);
        option.value = value;
        option.selected = Array.isArray(spec.value)
          ? spec.value.includes(value)
          : value === spec.value;
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
    input.required = !spec.optional && spec.type !== 'multiselect';
    if (spec.pattern) input.pattern = spec.pattern;
    if (spec.inputMode) input.inputMode = spec.inputMode;
    if (spec.max !== undefined) {
      if (spec.type === 'number') input.max = spec.max;
      else input.maxLength = spec.max;
    }
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
          spec.type === 'multiselect'
            ? [...input.selectedOptions].map((o) => o.value)
            : spec.type === 'number'
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
$('modal').addEventListener('close', () => {
  if (!$('modal').open) $('modal-content').replaceChildren();
});
$('modal').addEventListener('cancel', () => $('modal-content').replaceChildren());
function clearModal() {
  $('modal').close();
  $('modal-content').replaceChildren();
}
window.addEventListener('pagehide', clearModal);
function renderAuth(register = false) {
  state.version++;
  clearModal();
  document.body.classList.remove('signed-in');
  closeNavigation();
  $('workspace-path').hidden = true;
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
  document.body.classList.add('signed-in');
  $('workspace-path').hidden = false;
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
    'Applications',
    'Files & links',
    'Devices',
    'Organization',
    'Catalog',
    'Device demo',
    'Account',
    'Security center',
  ];
  if (state.principal.platform_role === 'platform_admin') views.push('Operator console');
  $('navigation').replaceChildren(...views.map(navigationButton));
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
  clearModal();
  state.view = view;
  $('workspace-path').textContent = `Workspace / ${view}`;
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
  if (view === 'Applications') {
    const version = state.version;
    const orgId = state.orgId;
    const path = orgPath();
    return operationsView({
      api,
      node,
      panel,
      button,
      title,
      table,
      empty,
      fieldsForm,
      notice,
      errorMessage,
      content,
      products: state.products,
      userId: state.principal.user_id,
      role: state.orgs.find((o) => o.id === orgId)?.role,
      orgPath: () => path,
      isCurrent: () => version === state.version && orgId === state.orgId && !!state.token,
      clearModal,
      showSecret,
      openAccount: () => navigate('Account'),
      modal: (...children) => {
        if (version !== state.version) return;
        $('modal-content').replaceChildren(...children);
        $('modal').showModal();
      },
    });
  }
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
    const workspaceDetails = node('details', undefined, 'panel compact-disclosure');
    workspaceDetails.append(
      node('summary', 'Workspace details'),
      details({ organization_id: org.id, kind: org.kind, role: org.role }),
    );
    const sections = [
      title(
        'Organization',
        `${org.name} · ${org.role} · Manage your workspace and its membership.`,
      ),
      panel(
        node('h2', 'Members'),
        table(
          ['Person', 'Role'],
          members.map((m) => [
            m.user_id === state.principal.user_id
              ? `${m.email || 'You'} (you)`
              : m.email || m.user_id,
            m.role,
          ]),
        ),
      ),
    ];
    const actions = node('div', undefined, 'workspace-actions');
    if (org.kind === 'personal')
      actions.append(
        panel(
          node('h2', 'Work with a team'),
          node(
            'p',
            'Your personal workspace is just for you. Create a team workspace to add other people and share access.',
          ),
        ),
      );
    if (org.kind !== 'personal' && ['owner', 'admin'].includes(org.role))
      actions.append(
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
                  ...(org.role === 'owner' ? [['owner', 'Owner']] : []),
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
    actions.append(
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
    sections.push(actions, workspaceDetails);
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
  const version = state.version;
  const token = state.token;
  const current = () => state.version === version && state.token === token;
  const sc = await api('/v1/security-center');
  const disclosure = (label, cls, ...children) => {
    const fold = node('details', undefined, cls);
    fold.append(node('summary', label), ...children);
    return fold;
  };
  const status = (label, attention = false) =>
    node('p', label, `security-state${attention ? ' attention' : ''}`);
  const openWorkspace = async (orgId, view) => {
    state.orgId = orgId;
    $('organization').value = orgId;
    await navigate(view);
  };
  const heading = title(
    'Security center',
    'Choose an action to protect your account or manage a device.',
  );
  heading.append(button('Refresh security status', () => navigate('Security center')));
  const account = panel(
    node('h2', 'Your account'),
    node('p', sc.account.email, 'security-email'),
    status(
      sc.account.email_verified ? 'Email verified' : 'Email not verified',
      !sc.account.email_verified,
    ),
    ...(state.principal.recovery_configured && !sc.account.email_verified
      ? [
          button(
            'Send verification email',
            async () => {
              const result = await api('/v1/auth/email/request', 'POST', {});
              if (current()) notice(result.message);
            },
            'primary',
          ),
        ]
      : []),
    button('Sign out', () => $('signout').click()),
    disclosure(
      'Account details',
      'security-disclosure',
      details({
        email_verified: sc.account.email_verified ? 'Yes' : 'No',
        authenticator_app: sc.account.authenticator_enabled ? 'Yes' : 'No',
        passkeys: sc.account.passkeys,
        platform_operator: sc.account.operator ? 'Yes' : 'No',
      }),
    ),
  );
  const mfa = mfaPanel(sc.account.authenticator_enabled);
  mfa.children[0].after(
    status(
      !state.principal.mfa_configured
        ? 'Unavailable on this deployment'
        : sc.account.authenticator_enabled
          ? 'Authenticator enabled'
          : 'Authenticator not enabled',
      state.principal.mfa_configured && !sc.account.authenticator_enabled,
    ),
  );
  const passkeys = await passkeyPanel('Security center');
  passkeys.children[0].after(
    status(
      passkeysAvailable
        ? `${sc.account.passkeys} passkey${sc.account.passkeys === 1 ? '' : 's'} registered`
        : 'Unavailable on this deployment or browser',
      passkeysAvailable && sc.account.passkeys === 0,
    ),
  );
  const actions = node('div', undefined, 'security-actions');
  actions.setAttribute('aria-label', 'Account security actions');
  actions.append(account, mfa, passkeys);
  const devices = panel(
    node('h2', 'Your devices'),
    sc.devices.length
      ? table(
          ['Device', 'Trust', 'Hardware evidence', 'Works offline until', 'Action'],
          sc.devices.map((d) => [
            node('span', d.device_id, 'mono'),
            badge(d.posture),
            d.attestation === 'unknown' ? 'None verified' : d.attestation,
            d.offline_lease_valid_until
              ? new Date(d.offline_lease_valid_until).toLocaleString()
              : '—',
            button(
              'Deactivate device',
              async () => {
                const until = d.offline_lease_valid_until
                  ? new Date(d.offline_lease_valid_until).toLocaleString()
                  : 'its existing lease expires';
                if (
                  !confirm(
                    `Deactivate this device and free its slot? It may still work offline until ${until}.`,
                  )
                )
                  return;
                await api(
                  `/v1/organizations/${encodeURIComponent(d.org_id)}/activations/${encodeURIComponent(d.activation_id)}/deactivate`,
                  'POST',
                );
                if (!current()) return;
                await navigate('Security center');
                notice('Device deactivated. Existing offline leases remain valid until expiry.');
              },
              'danger',
            ),
          ]),
        )
      : empty('You have not activated any devices.'),
  );
  return [
    heading,
    actions,
    devices,
    ...sc.organizations.map((o) => {
      const controls = node('div', undefined, 'actions');
      controls.append(
        ...(o.permissions.some((x) => x.permission === 'ops:read')
          ? [
              button(
                'Manage application monitoring',
                () => openWorkspace(o.id, 'Applications'),
                'primary',
              ),
            ]
          : []),
        button('Manage organization', () => openWorkspace(o.id, 'Organization')),
      );
      return panel(
        node('h2', `${o.name} — ${o.role}`),
        controls,
        disclosure(
          'View role permissions',
          'security-disclosure security-permissions',
          table(
            ['You may', 'Permission'],
            o.permissions.map((x) => [x.description, node('span', x.permission, 'mono')]),
          ),
        ),
      );
    }),
    ...(sc.recommendations.length
      ? [
          disclosure(
            `Recommendations (${sc.recommendations.length})`,
            'panel security-disclosure',
            ...sc.recommendations.map((r) => node('p', r)),
          ),
        ]
      : []),
    disclosure(
      'What we collect · Privacy & retention',
      'panel security-disclosure security-privacy',
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

async function passkeyPanel(returnView = 'Account') {
  const version = state.version;
  const token = state.token;
  const current = () => state.version === version && state.token === token;
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
              if (!current()) return;
              await navigate(returnView);
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
        if (!current()) return;
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
        if (!cred || !current()) return;
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
        if (!current()) return;
        await navigate(returnView);
        notice('Passkey added. You can now sign in with it.');
      },
    ),
  );
  return card;
}

function mfaPanel(enabled = state.principal.mfa_enabled) {
  const version = state.version;
  const token = state.token;
  const current = () => state.version === version && state.token === token;
  if (!state.principal.mfa_configured)
    return panel(
      node('h2', 'Authenticator protection'),
      node('p', 'Authenticator setup is not configured on this deployment.'),
    );
  const card = panel(node('h2', 'Authenticator protection'));
  if (
    state.principal.operator_mfa_required &&
    state.principal.platform_role === 'platform_admin' &&
    !enabled
  )
    card.append(node('p', 'Enroll an authenticator before using operator administration.'));
  if (enabled) {
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
          if (!current()) return;
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
      'Protection is not enabled yet. Setup has three steps: generate a manual key, add that key to your authenticator app, then confirm it here with your password and a six-digit code. Keep existing phone entries until the new setup is confirmed.',
    ),
    fieldsForm(
      [{ name: 'password', label: 'Current password', type: 'password' }],
      'Set up authenticator',
      async (data, form) => {
        const setup = await api('/v1/auth/mfa/begin', 'POST', data);
        form.reset();
        if (!current()) return;
        // Setup secret exists only in this view. Navigation removes it; nothing goes to storage or a QR service.
        const secret = node('input');
        secret.readOnly = true;
        secret.value = setup.setup_key;
        secret.setAttribute('aria-label', 'Authenticator setup key');
        card.replaceChildren(
          node('h2', 'Confirm your authenticator'),
          node(
            'p',
            'Step 1: In your authenticator app, add a manual time-based entry named Rokela Bai Bureh Warrior using the key below. Choose six digits and a 30-second period. There is no QR code in this setup.',
          ),
          secret,
          node(
            'p',
            `This key expires at ${new Date(setup.expires_at).toLocaleTimeString()}. Starting setup again creates a new key; codes from older pending entries will not match. Leaving this page removes the displayed key.`,
          ),
          node(
            'p',
            'Step 2: Enter your Warrior password again and the current code from the entry you just added. Click Enable authenticator. Protection is enabled only after confirmation succeeds.',
          ),
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
              if (!current()) return;
              state.token = '';
              state.principal = null;
              renderAuth();
              showSecret(
                result.recovery_codes.join(' '),
                'Save your single-use recovery codes',
                'One-time recovery codes',
              );
              notice(
                'Step 3 complete: authenticator enabled. Save the recovery codes privately. All sessions signed out; wait for a new authenticator code before signing in again.',
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
  const statusBox = panel();
  const renderStatus = (value) => {
    const technical = node('details', undefined, 'compact-disclosure');
    technical.append(node('summary', 'Installation details'), details(value));
    statusBox.replaceChildren(
      node('h2', 'This browser installation'),
      node(
        'p',
        value.activation_id === 'Not activated'
          ? 'Not activated. Enter a license key below to get started.'
          : `Activated for ${value.product}.`,
      ),
      technical,
    );
  };
  renderStatus(status);
  const output = node('div');
  output.setAttribute('role', 'status');
  output.setAttribute('aria-live', 'polite');
  const run = async (action) => {
    const value = await action();
    renderStatus(await device.summary());
    const evidence = node('details', undefined, 'compact-disclosure');
    evidence.append(node('summary', 'Result details'), node('pre', JSON.stringify(value, null, 2)));
    output.replaceChildren(
      node('p', `Result: ${value.state || value.status || 'Completed'}`),
      evidence,
    );
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
        'Activate first, then validate access, refresh your lease or verify it offline. Offline verification uses the public keys cached at activation.',
      ),
      (() => {
        const actions = node('div', undefined, 'actions');
        actions.append(
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
        );
        return actions;
      })(),
      output,
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
  const overview = node('div');
  overview.setAttribute('aria-live', 'polite');
  const loadOverview = async () => {
    overview.replaceChildren(node('p', 'Loading audit status…'));
    try {
      const anchors = await api('/v1/admin/audit/anchors?limit=10');
      overview.replaceChildren(
        table(
          ['Audit protection', 'Current evidence'],
          [
            ['External witness', anchors.configured ? 'Configured' : 'Not configured'],
            [
              'Latest publication attempt',
              anchors.items[0]
                ? `${anchors.items[0].status} · ${new Date(anchors.items[0].created_at).toLocaleString()}`
                : 'No publication recorded',
            ],
          ],
        ),
        node(
          'p',
          'Configuration and publication records do not prove independent retention or retrieval. Missing or old evidence does not establish current protection.',
        ),
        node('h3', 'Recent audit publications'),
        table(
          ['Received', 'Result', 'Chains', 'Events'],
          anchors.items.map((item) => [
            new Date(item.created_at).toLocaleString(),
            item.status,
            item.chains,
            item.events,
          ]),
        ),
      );
    } catch {
      overview.replaceChildren(
        node(
          'p',
          'Audit status unavailable. Retry or check your operator access; this is not evidence that protection is active.',
        ),
      );
    }
  };
  const chainResult = node('p', 'Audit chains have not been checked in this view.');
  chainResult.setAttribute('aria-live', 'polite');
  const investigation = node('a', 'Open IT incident brief in GitHub');
  investigation.href =
    'https://github.com/baimasonga/security-system/actions/workflows/it-incident-brief.yml';
  const recovery = node('a', 'Open synthetic recovery checks in GitHub');
  recovery.href =
    'https://github.com/baimasonga/security-system/actions/workflows/recovery-exercise.yml';
  sections.push(
    panel(
      node('h2', 'Operations overview'),
      node('p', 'Inspect audit protection and open the monitoring and investigation tools.'),
      button('Refresh audit status', loadOverview),
      overview,
      button('Check audit integrity', async () => {
        chainResult.textContent = 'Checking audit chains…';
        try {
          const result = await api('/v1/admin/audit/verify');
          chainResult.textContent =
            result.ok === true
              ? 'Audit chains are internally consistent. This does not replace an independent witness.'
              : 'Audit integrity check failed. Review the audit evidence before relying on this history.';
        } catch {
          chainResult.textContent =
            'Audit integrity could not be checked. No successful result is established.';
        }
      }),
      chainResult,
      node('h3', 'Application monitoring'),
      node(
        'p',
        'Open an application to inspect its component reports, Warrior checks, incidents and recovery evidence.',
      ),
      button('Open application monitoring', () => navigate('Applications')),
      node('h3', 'IT investigation'),
      node(
        'p',
        'The independent public checks run in GitHub. Open the workflow, select Run workflow, then read its Summary. They do not test authenticated workflows or establish root cause.',
      ),
      investigation,
      node('h3', 'Recovery readiness'),
      node(
        'p',
        'Synthetic restore tests run separately in GitHub. Their success does not verify a production backup or a production restore. Review application recovery evidence separately.',
      ),
      recovery,
    ),
  );
  await loadOverview();
  const mobileReport = node('div');
  mobileReport.setAttribute('aria-live', 'polite');
  mobileReport.append(
    node('p', 'Select Refresh APK downloads to retrieve the current release counter.'),
  );
  sections.push(
    panel(
      node('h2', 'Mobile app downloads'),
      node('p', 'Rokela PDF for Android · direct APK distribution through GitHub'),
      button('Refresh APK downloads', async () => {
        mobileReport.replaceChildren(node('p', 'Loading download evidence…'));
        try {
          const result = await api('/v1/admin/mobile-distribution');
          if (result.status !== 'available') {
            mobileReport.replaceChildren(
              node('p', 'Download evidence unavailable. No download count is established.'),
            );
            return;
          }
          mobileReport.replaceChildren(
            table(
              ['Current APK evidence', 'Value'],
              [
                ['GitHub download count', result.downloads],
                ['Asset ID', result.asset_id],
                ['Asset created', new Date(result.created_at).toLocaleString()],
                ['Asset updated', new Date(result.updated_at).toLocaleString()],
                ['Checked', new Date(result.checked_at).toLocaleString()],
              ],
            ),
          );
        } catch {
          mobileReport.replaceChildren(
            node('p', 'Download evidence unavailable. No download count is established.'),
          );
        }
      }),
      mobileReport,
      node(
        'p',
        'This is GitHub’s counter for the current APK asset, not unique people, verified installs or a lifetime total. Replacing the asset can reset it. Results may be cached for five minutes.',
      ),
      node('h3', 'App usage, devices and country'),
      node(
        'p',
        'GitHub downloads do not report app usage. Choose Mobile app usage in this console to inspect reports from compatible Android builds. Country uses a separately configured local IP-country lookup; no GPS is collected.',
      ),
    ),
  );

  const usageReport = node('div');
  usageReport.setAttribute('aria-live', 'polite');
  usageReport.append(node('p', 'Select Refresh mobile usage to load received app reports.'));
  const geoCredit = node('a', 'IP Geolocation by DB-IP');
  geoCredit.href = 'https://db-ip.com/';
  sections.push(
    panel(
      node('h2', 'Mobile app usage'),
      node('p', 'Rokela Android · anonymous client reports · rolling 30-day window'),
      button('Refresh mobile usage', async () => {
        usageReport.replaceChildren(node('p', 'Loading mobile reports…'));
        try {
          const result = await api('/v1/admin/mobile-analytics');
          usageReport.replaceChildren(
            table(
              ['Usage evidence', 'Value'],
              [
                ['Received reports', result.reports],
                ['Reporting installations · 24 hours', result.active_installations_1d],
                ['Reporting installations · 7 days', result.active_installations_7d],
                ['Reporting installations · 30 days', result.active_installations_30d],
                [
                  'Last report received',
                  result.last_received_at
                    ? new Date(result.last_received_at).toLocaleString()
                    : 'No app reports received',
                ],
                [
                  'Country lookup',
                  result.country_lookup_configured
                    ? 'Configured; unknown results remain possible'
                    : 'Not configured; country is unknown',
                ],
              ],
            ),
            ...[
              ['Home-screen tool selections and launches', result.features],
              ['Device classes', result.devices],
              ['App versions', result.versions],
              ['Android major versions', result.android_versions],
              ['Reports by received day', result.daily_reports],
              ['Countries (at least five installations)', result.countries],
            ].map(([heading, rows]) =>
              panel(
                node('h3', heading),
                table(
                  ['Category', 'Reports', 'Reporting installations'],
                  rows.map((row) => [row.label, row.events, row.installations]),
                ),
              ),
            ),
          );
        } catch {
          usageReport.replaceChildren(
            node('p', 'Mobile reports unavailable. No usage count is established.'),
          );
        }
      }),
      usageReport,
      node(
        'p',
        'Reports are unverified app assertions, not unique people, verified devices or completed document operations. Reinstallation can create a new identifier. Offline delivery can be delayed. Version 0 and unknown device values mean metadata was unavailable. Country is approximate and can be affected by VPNs; small country groups are not shown.',
      ),
      node(
        'p',
        'No GPS, document contents, account details or raw IP addresses are stored in these analytics. Reports expire after 30 days. Device/version categories can overlap and must not be added to estimate unique people.',
      ),
      geoCredit,
    ),
  );
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
