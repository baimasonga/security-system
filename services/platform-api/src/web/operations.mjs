// Each visit owns its scope and lifecycle. Never reuse a mutable global workspace or retain secrets.
const enc = encodeURIComponent;
const choices = (values) => values.map((v) => [v, v.replaceAll('_', ' ')]);
const reasons = choices([
  'initial_setup',
  'owner_transfer',
  'maintenance',
  'retirement',
  'restore',
  'security_response',
  'routine_rotation',
  'config_change',
  'assignment',
]);
const kinds = choices([
  'service',
  'database',
  'storage',
  'worker',
  'scanner',
  'desktop',
  'provider',
]);
const reason = () => ({ name: 'reason', label: 'Reason', options: reasons });
const code = () => ({
  name: 'code',
  label: 'Code (permanent)',
  pattern: '[a-z][a-z0-9-]{1,47}',
  max: 48,
});
const when = (value) => (value ? new Date(value).toLocaleString() : '—');

export async function operationsView(ui) {
  const { node, panel, button, title, table, empty, fieldsForm } = ui;
  const base = `${ui.orgPath()}/operations/applications`;
  let generation = 0;
  const current = (n) => ui.isCurrent() && n === generation;
  async function show(load) {
    const n = ++generation;
    ui.clearModal();
    ui.content.replaceChildren(node('div', 'Loading application inventory…', 'loading'));
    try {
      const page = await load();
      if (current(n)) {
        ui.content.replaceChildren(...page);
        return true;
      }
    } catch (e) {
      if (current(n)) {
        ui.content.replaceChildren(
          panel(
            node('h1', 'Applications'),
            empty('Could not load this view.'),
            button('Try again', refresh(load)),
          ),
        );
        ui.errorMessage(e);
        return true; // Keep one-time delivery possible if only the post-mutation refresh failed.
      }
    }
  }
  const refresh = (load) => () => show(load);
  function form(specs, label, action) {
    const formGeneration = generation;
    return fieldsForm(specs, label, async (data, element) => {
      if (!current(formGeneration)) return;
      // Clear the submitted factor before awaiting any network operation, including refusals.
      const mfa = element.elements.namedItem('mfa_code');
      if (mfa) mfa.value = '';
      const n = generation;
      try {
        await action(data, n);
      } catch (e) {
        if (current(n)) {
          if (e.status === 409)
            ui.notice(
              'The record changed or a lifecycle/credential limit prevents this action. Refresh before retrying; use a fresh authenticator code.',
              true,
            );
          else if (e.status === 401 && data.mfa_code)
            ui.notice(
              'Authentication failed. Use a fresh authenticator code; sign in again if your session expired.',
              true,
            );
          else ui.errorMessage(e);
        }
      }
    });
  }
  function header(label, description, parent) {
    return [title(label, description), ...(parent ? [button('Back', refresh(parent))] : [])];
  }
  async function list(path) {
    const out = [];
    let cursor;
    do {
      const page = await ui.api(`${path}?limit=100${cursor ? `&cursor=${enc(cursor)}` : ''}`);
      out.push(...page.items);
      cursor = page.next_cursor;
      // Inventory is bounded server-side. A corrupt cursor must not create an unbounded loop.
      if (out.length > 10000) throw new Error('Too many records. Please contact support.');
    } while (cursor && ui.isCurrent());
    return out;
  }
  // List pages fetch the first page explicitly so disabled/forbidden rollout states are handled visibly.
  async function listing(path, columns, renderRow) {
    let cursor;
    const rows = [];
    const wrap = node('div');
    const load = async () => {
      const n = generation;
      const page = await ui.api(`${path}?limit=25${cursor ? `&cursor=${enc(cursor)}` : ''}`);
      if (!current(n)) return;
      rows.push(...page.items);
      cursor = page.next_cursor;
      const more = button('Load more', load);
      more.hidden = !cursor;
      wrap.replaceChildren(
        rows.length ? table(columns, rows.map(renderRow)) : empty('No records yet.'),
        more,
      );
    };
    await load();
    return wrap;
  }
  async function appFields(row) {
    const members = (await ui.api(`${ui.orgPath()}/members`)).items;
    const products = ui.products.map((p) => [p.id, p.name]);
    if (row?.product_id && !ui.products.some((p) => p.id === row.product_id))
      products.push([row.product_id, 'Existing product (not available in catalog)']);
    return [
      {
        name: 'owner_user_id',
        label: 'Owner',
        value: row?.owner_user_id ?? ui.userId,
        options: members.map((m) => [
          m.user_id,
          m.user_id === ui.userId ? 'You' : m.email || m.user_id,
        ]),
      },
      {
        name: 'criticality',
        label: 'Criticality',
        value: row?.criticality ?? 'medium',
        options: choices(['low', 'medium', 'high', 'critical']),
      },
      {
        name: 'product_id',
        label: 'Linked licensing product (optional)',
        optional: true,
        value: row?.product_id ?? '',
        options: [['', 'No product'], ...products],
      },
    ];
  }
  function lookup(prefix, open) {
    return panel(
      node('h2', 'Open retained record'),
      node(
        'p',
        'Archived records are hidden from lists. Open a known record ID to review history or revoke credentials.',
      ),
      form(
        [{ name: 'id', label: 'Record ID', pattern: `${prefix}_[a-f0-9]{24}`, max: 28 }],
        'Open record',
        async ({ id }) => show(() => open(id)),
      ),
    );
  }
  async function applications() {
    const rows = await listing(base, ['Application', 'State', 'Criticality', ''], (a) => [
      a.code,
      a.state,
      a.criticality,
      button(
        'Open',
        refresh(() => application(a.id)),
      ),
    ]);
    return [
      ...header(
        'Applications',
        'Register your systems and their components. Inventory does not imply active monitoring.',
      ),
      panel(node('h2', 'Your applications'), rows),
      lookup('opa', application),
      panel(
        node('h2', 'Register application'),
        form([code(), ...(await appFields()), reason()], 'Register application', async (data) => {
          await ui.api(base, 'POST', { ...data, product_id: data.product_id || null });
          await show(applications);
        }),
      ),
    ];
  }
  function lifecycle(row, path, reload) {
    if (row.state === 'archived')
      return empty('Archived permanently. History is retained; this code cannot be reused.');
    return form(
      [
        {
          name: 'action',
          label: 'Lifecycle action',
          options: [
            [
              row.state === 'active' ? 'disabled' : 'active',
              row.state === 'active' ? 'Disable' : 'Reactivate',
            ],
            ['archived', 'Archive permanently'],
          ],
        },
        reason(),
      ],
      'Apply lifecycle change',
      async ({ action, reason }) => {
        if (
          action === 'archived' &&
          !window.confirm(
            'Archive permanently? Descendants stop accepting new configuration and credentials. This code cannot be reused.',
          )
        )
          return;
        await ui.api(path, action === 'archived' ? 'DELETE' : 'PATCH', {
          expected_version: row.version,
          reason,
          ...(action === 'archived' ? {} : { state: action }),
        });
        await show(reload);
      },
    );
  }
  async function application(id) {
    const path = `${base}/${enc(id)}`;
    const a = await ui.api(path);
    const reload = () => application(id);
    const rows = await listing(
      `${path}/environments`,
      ['Environment', 'Kind', 'State', ''],
      (e) => [
        e.code,
        e.kind,
        e.state,
        button(
          'Open',
          refresh(() => environment(id, e.id)),
        ),
      ],
    );
    return [
      ...header(a.code, `Application · ${a.state} · version ${a.version}`, applications),
      button('Refresh', refresh(reload)),
      panel(node('h2', 'Environments'), node('p', `Application ID: ${a.id}`), rows),
      lookup('ope', (envId) => environment(id, envId)),
      ...(a.state === 'active'
        ? [
            panel(
              node('h2', 'Add environment'),
              form(
                [
                  code(),
                  {
                    name: 'kind',
                    label: 'Environment kind',
                    options: choices(['development', 'staging', 'production']),
                  },
                  reason(),
                ],
                'Add environment',
                async (data) => {
                  await ui.api(`${path}/environments`, 'POST', data);
                  await show(reload);
                },
              ),
            ),
          ]
        : []),
      ...(a.state !== 'archived'
        ? [
            panel(
              node('h2', 'Application settings'),
              form([...(await appFields(a)), reason()], 'Save application', async (data) => {
                await ui.api(path, 'PATCH', {
                  ...data,
                  product_id: data.product_id || null,
                  expected_version: a.version,
                });
                await show(reload);
              }),
            ),
          ]
        : []),
      panel(node('h2', 'Application lifecycle'), lifecycle(a, path, reload)),
    ];
  }
  function dependencyField(components, row) {
    return {
      name: 'dependency_ids',
      label: 'Dependencies in this environment',
      type: 'multiselect',
      value: row?.dependency_ids ?? [],
      options: components
        .filter((c) => c.id !== row?.id && c.state !== 'archived')
        .map((c) => [c.id, c.code])
        .concat(
          (row?.dependency_ids ?? [])
            .filter((id) => !components.some((c) => c.id === id && c.state !== 'archived'))
            .map((id) => [id, `${id} (retained dependency)`]),
        ),
    };
  }
  async function healthPanel(path) {
    try {
      const result = await ui.api(`${path}/health`);
      return panel(
        node('h2', 'Reported health'),
        node(
          'p',
          'Backend assertions, not independent probes. Missing and stale reports do not establish availability. Refresh to update.',
        ),
        result.components.length
          ? table(
              ['Component', 'Health with dependencies', 'Own report', 'Last received'],
              result.components.map((c) => [
                c.code,
                c.status,
                c.reported_status,
                when(c.received_at),
              ]),
            )
          : empty('No components to monitor.'),
      );
    } catch (e) {
      if (e.status === 401) throw e;
      return panel(
        node('h2', 'Reported health'),
        empty(
          e.status === 404
            ? 'Health reporting is not enabled for this workspace.'
            : 'Health evidence is currently unavailable.',
        ),
      );
    }
  }
  async function historyPanel(path) {
    try {
      const result = await ui.api(`${path}/history`);
      return panel(
        node('h2', 'Recent event history'),
        node(
          'p',
          'Hourly backend observations over the last 24 hours. Empty hours are gaps, not successful checks. Boundary hours include the whole stored bucket.',
        ),
        ...(result.truncated
          ? [
              node(
                'p',
                'This interval contains more than 1,000 rows. Only the first 1,000 are shown.',
              ),
            ]
          : []),
        result.items.length
          ? table(
              ['Hour', 'Event type', 'Reported outcome', 'Count'],
              result.items.map((r) => [when(r.hour), r.type, r.outcome, String(r.count)]),
            )
          : empty('No retained observations in this interval.'),
      );
    } catch (e) {
      if (e.status === 401) throw e;
      return panel(
        node('h2', 'Recent event history'),
        empty(
          e.status === 404
            ? 'Health history is not enabled for this workspace.'
            : 'History evidence is currently unavailable.',
        ),
      );
    }
  }
  async function environment(appId, id) {
    const appPath = `${base}/${enc(appId)}`;
    const path = `${appPath}/environments/${enc(id)}`;
    const [a, e, components] = await Promise.all([
      ui.api(appPath),
      ui.api(path),
      list(`${path}/components`),
    ]);
    const reload = () => environment(appId, id);
    const parent = () => application(appId);
    const writable = a.state === 'active' && e.state === 'active';
    const rows = components.map((c) => [
      c.code,
      c.kind,
      c.state,
      button(
        'Open',
        refresh(() => component(appId, id, c.id)),
      ),
    ]);
    return [
      ...header(
        `${a.code} / ${e.code}`,
        `${e.kind} environment · ${e.state} · version ${e.version}`,
        parent,
      ),
      button('Refresh', refresh(reload)),
      await healthPanel(path),
      panel(
        node('h2', 'Components'),
        rows.length ? table(['Component', 'Kind', 'State', ''], rows) : empty('No components yet.'),
      ),
      ...(writable
        ? [
            panel(
              node('h2', 'Add component'),
              form(
                [
                  code(),
                  { name: 'kind', label: 'Component kind', options: kinds },
                  dependencyField(components),
                  reason(),
                ],
                'Add component',
                async (data) => {
                  await ui.api(`${path}/components`, 'POST', data);
                  await show(reload);
                },
              ),
            ),
          ]
        : []),
      lookup('opm', (componentId) => component(appId, id, componentId)),
      node('p', `Environment ID: ${e.id}`),
      await credentials(path, writable, reload),
      panel(
        node('h2', 'Environment lifecycle'),
        a.state === 'active'
          ? lifecycle(e, path, reload)
          : empty('Reactivate the application before changing this environment.'),
      ),
    ];
  }
  async function component(appId, envId, id) {
    const path = `${base}/${enc(appId)}/environments/${enc(envId)}/components`;
    const [c, components, a, e] = await Promise.all([
      ui.api(`${path}/${enc(id)}`),
      list(path),
      ui.api(`${base}/${enc(appId)}`),
      ui.api(`${base}/${enc(appId)}/environments/${enc(envId)}`),
    ]);
    const writable = a.state === 'active' && e.state === 'active';
    const parent = () => environment(appId, envId);
    const reload = () => component(appId, envId, id);
    return [
      ...header(c.code, `${c.kind} · ${c.state} · version ${c.version}`, parent),
      button('Refresh', refresh(reload)),
      node('p', `Component ID: ${c.id}`),
      await historyPanel(`${path}/${enc(id)}`),
      ...(writable && c.state !== 'archived'
        ? [
            panel(
              node('h2', 'Component settings'),
              form(
                [
                  { name: 'kind', label: 'Component kind', value: c.kind, options: kinds },
                  dependencyField(components, c),
                  reason(),
                ],
                'Save component',
                async (data) => {
                  await ui.api(`${path}/${enc(id)}`, 'PATCH', {
                    ...data,
                    expected_version: c.version,
                  });
                  await show(reload);
                },
              ),
            ),
          ]
        : []),
      panel(
        node('h2', 'Component lifecycle'),
        writable
          ? lifecycle(c, `${path}/${enc(id)}`, reload)
          : empty('Reactivate the application and environment before changing this component.'),
      ),
    ];
  }
  const factor = () => ({
    name: 'mfa_code',
    label: 'Fresh authenticator code',
    type: 'password',
    pattern: '[0-9]{6}',
    min: 6,
    max: 6,
    autocomplete: 'one-time-code',
    inputMode: 'numeric',
  });
  const ttl = () => ({
    name: 'ttl_days',
    label: 'Expires after (days)',
    type: 'number',
    value: 30,
    min: 1,
    max: 90,
  });
  async function credentials(path, writable, reload) {
    const section = panel(
      node('h2', 'Integration credentials'),
      node(
        'p',
        'Credentials authorize backend event reporting when the collector rollout is enabled; they do not prove that a sender is connected. Enroll an authenticator under Account before issuing, rotating or revoking. A failed request consumes its code; use a new code for every attempt. If a response is lost, refresh the credential list before issuing again; an old secret cannot be recovered.',
      ),
    );
    function mutation(action, row) {
      const rotate = action === 'rotate';
      const issue = action === 'issue';
      return form(
        [
          ...(rotate || issue ? [ttl()] : []),
          ...(rotate
            ? [
                {
                  name: 'overlap_seconds',
                  label: 'Old credential overlap (seconds)',
                  type: 'number',
                  value: 0,
                  min: 0,
                  max: 3600,
                },
              ]
            : []),
          reason(),
          factor(),
        ],
        issue ? 'Issue credential' : rotate ? 'Rotate credential' : 'Revoke credential',
        async (data, n) => {
          const { ttl_days, ...body } = data;
          if (ttl_days) body.ttl_seconds = ttl_days * 86400;
          if (issue) body.purpose = 'events:write';
          if (
            !issue &&
            !rotate &&
            !window.confirm(
              'Revoke this credential permanently? Connected senders will lose access.',
            )
          )
            return;
          const result = await ui.api(
            `${path}/credentials${issue ? '' : `/${enc(row.id)}/${action}`}`,
            'POST',
            body,
          );
          if (!current(n)) return; // A late secret must never appear in another view/workspace.
          const rendered = await show(reload);
          if (rendered && ui.isCurrent() && result.token)
            ui.showSecret(
              result.token,
              'Save your integration credential',
              'One-time integration credential',
            );
        },
      );
    }
    try {
      section.append(
        await listing(
          `${path}/credentials`,
          ['Credential', 'Purpose', 'Expires', 'State', ''],
          (c) => {
            const status = c.revoked_at
              ? 'Revoked'
              : new Date(c.expires_at).getTime() <= Date.now()
                ? 'Expired'
                : 'Active';
            const actions = node('div');
            if (status === 'Active') {
              if (writable)
                actions.append(
                  button('Rotate', () =>
                    ui.modal(node('h2', 'Rotate credential'), mutation('rotate', c)),
                  ),
                );
              // Emergency revocation stays available even with disabled/archived parents.
              actions.append(
                button(
                  'Revoke',
                  () => ui.modal(node('h2', 'Revoke credential'), mutation('revoke', c)),
                  'danger',
                ),
              );
            }
            return [c.id, c.purpose, when(c.expires_at), status, actions];
          },
        ),
      );
      if (writable) section.append(node('h3', 'New credential'), mutation('issue'));
    } catch (e) {
      if (e.status === 404)
        section.append(empty('Credential management is unavailable in this deployment.'));
      else throw e;
    }
    return section;
  }
  if (!['admin', 'owner'].includes(ui.role))
    return [
      title(
        'Applications',
        'Only organization owners and admins can manage application inventory and credentials.',
      ),
    ];
  try {
    return await applications();
  } catch (e) {
    if (e.status === 404)
      return [title('Applications', 'Application management is unavailable in this deployment.')];
    throw e;
  }
}
