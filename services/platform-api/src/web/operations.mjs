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

// Summaries describe only the bounded evidence returned by the existing scoped API.
export function summarizePosture(view) {
  if (!view)
    return {
      available: false,
      rank: 2,
      findingText: 'Unknown',
      scanText: 'Reporting unavailable',
      restoreText: 'Unknown',
      partial: true,
    };
  const latest = (items) =>
    items.reduce(
      (a, b) => (!a || new Date(b.completed_at) > new Date(a.completed_at) ? b : a),
      null,
    );
  const scan = latest(view.scans.items);
  const restore = latest(view.recovery.items.filter((r) => r.kind === 'restore'));
  const open = view.findings.items.filter((f) => ['open', 'acknowledged'].includes(f.state));
  const critical = open.filter((f) => f.severity === 'critical').length;
  const high = open.filter((f) => f.severity === 'high').length;
  const rank = critical
    ? 0
    : high
      ? 1
      : scan?.outcome === 'failed' || restore?.outcome === 'failed'
        ? 2
        : !scan || !restore || scan.freshness !== 'current' || restore.freshness !== 'current'
          ? 3
          : open.length
            ? 4
            : 5;
  const describe = (r) => `${r.outcome} · ${r.freshness} · ${when(r.completed_at)}`;
  return {
    available: true,
    rank,
    findingText: `${open.length} shown · ${critical} critical · ${high} high${view.findings.truncated ? ' · more findings not shown' : ''}`,
    scanText: scan ? describe(scan) : 'No scan report shown',
    restoreText: restore ? describe(restore) : 'No restore report shown',
    partial: view.scans.truncated || view.findings.truncated || view.recovery.truncated,
  };
}

// Static responder instructions. Codes never become URLs, scripts or infrastructure actions.
const responseGuides = {
  investigate_component: {
    title: 'Investigate component',
    steps: [
      'Assign a responder and acknowledge the incident using Manage incident. Check the affected component, dependencies and observation timestamps.',
      'Compare recent deployment and configuration changes with the failure window. Inspect provider diagnostics without copying tokens, document contents or private links.',
      'If a deployment is implicated, use the approved rollback procedure only after checking schema compatibility. Preserve evidence and customer documents.',
    ],
    recovery:
      'Require fresh healthy observations and a synthetic application check before resolving. Resolving an incident does not repair the component.',
  },
  check_scanner: {
    title: 'Check scanner',
    steps: [
      'Check private scanner connectivity, service readiness, memory pressure and signature-update status in the hosting dashboard.',
      'Distinguish scanner unavailability from a malware detection. Preserve rejected-file evidence without opening or downloading suspected malware.',
      'Never disable scanning or allow quarantined files through to restore availability. Escalate unavailable scanning to the service maintainer.',
    ],
    recovery:
      'Require fresh healthy scanner observations, a clean synthetic file check and a controlled malware refusal check before resolving.',
  },
  check_converter: {
    title: 'Check converter',
    steps: [
      'Check converter readiness, worker backlog, memory and timeout limits in the hosting dashboard.',
      'Use a small synthetic document to distinguish a service failure from an unsupported input. Do not upload customer documents for diagnostics.',
      'Compare the failure window with converter or deployment changes. Use an approved compatible rollback if necessary; preserve original files.',
    ],
    recovery:
      'Require fresh healthy observations and successful synthetic conversion with an output-content check before resolving.',
  },
  check_storage: {
    title: 'Check storage',
    steps: [
      'Check storage-provider availability, capacity and authorization failures using the approved provider dashboard.',
      'Check the configured bucket and credential permissions without displaying keys. Do not delete or replace the existing bucket or customer objects.',
      'Test a disposable synthetic object through the application upload and authorized download paths. Retain access controls and scanner checks.',
    ],
    recovery:
      'Require fresh healthy observations and successful synthetic upload, authorized download and cleanup before resolving. Backup success does not prove restoration.',
  },
  check_email: {
    title: 'Check email delivery',
    steps: [
      'Check provider acceptance, sending limits, sender-domain authentication and the application delivery backlog.',
      'Check authentication-hook configuration separately from transfer notifications. Keep email confirmation enabled; never substitute an HTTP API token for an SMTP password.',
      'Use an address controlled by the responder for an authorized delivery test. Do not copy confirmation links, codes or recipient addresses into incident evidence.',
    ],
    recovery:
      'Require fresh successful delivery observations and a controlled inbox and confirmation check before resolving. Provider acceptance alone is not inbox delivery.',
  },
};
export function responseGuide(code) {
  if (typeof code !== 'string' || !Object.hasOwn(responseGuides, code)) return null;
  return {
    ...responseGuides[code],
    escalation:
      'Escalate to the application owner and the affected provider if service remains unavailable, failures recur, or recovery cannot be verified. Use approved private contact channels; never post secrets or customer data.',
  };
}

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
              data.mfa_code
                ? 'The record changed or a lifecycle/credential limit prevents this action. Refresh before retrying; use a fresh authenticator code.'
                : 'The record changed or a limit prevents this action. Refresh before retrying.',
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
      node('span', a.state, a.state === 'active' ? 'badge' : 'badge inactive'),
      node('span', a.criticality, 'badge neutral'),
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
      button('Review security overview', refresh(securityOverview)),
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
  async function securityOverview() {
    const n = generation;
    const apps = await ui.api(`${base}?limit=10`);
    if (!current(n)) return [];
    const appItems = apps.items.slice(0, 10);
    let partial = Boolean(apps.next_cursor) || apps.items.length > 10;
    const scopes = [];
    // Bounded batches preserve responsiveness and stop new reads after navigation.
    for (let offset = 0; offset < appItems.length; offset += 4) {
      if (!current(n)) return [];
      const batch = appItems.slice(offset, offset + 4);
      const pages = await Promise.all(
        batch.map((a) => ui.api(`${base}/${enc(a.id)}/environments?limit=5`)),
      );
      if (!current(n)) return [];
      for (let i = 0; i < batch.length; i++) {
        partial ||= Boolean(pages[i].next_cursor) || pages[i].items.length > 5;
        for (const e of pages[i].items.slice(0, 5)) scopes.push({ app: batch[i], env: e });
      }
    }
    const reports = [];
    for (let offset = 0; offset < scopes.length; offset += 4) {
      if (!current(n)) return [];
      const batch = scopes.slice(offset, offset + 4);
      const views = await Promise.all(
        batch.map(async (scope) => {
          try {
            return await ui.api(
              `${base}/${enc(scope.app.id)}/environments/${enc(scope.env.id)}/security`,
            );
          } catch (error) {
            if ([401, 403].includes(error.status)) throw error;
            return null;
          }
        }),
      );
      if (!current(n)) return [];
      for (let i = 0; i < batch.length; i++) {
        const summary = summarizePosture(views[i]);
        partial ||= summary.partial;
        reports.push({ ...batch[i], ...summary });
      }
    }
    reports.sort(
      (a, b) =>
        a.rank - b.rank ||
        a.app.code.localeCompare(b.app.code) ||
        a.env.code.localeCompare(b.env.code),
    );
    const rows = reports.map((r) => {
      const label = `${r.app.code} / ${r.env.code}`;
      const action = button(
        r.available ? 'Review' : 'Open environment',
        refresh(() =>
          r.available ? posturePage(r.app.id, r.env.id) : environment(r.app.id, r.env.id),
        ),
      );
      action.setAttribute('aria-label', `${r.available ? 'Review' : 'Open'} ${label}`);
      return [
        label,
        `${r.app.state} / ${r.env.state}`,
        r.findingText,
        r.scanText,
        r.restoreText,
        action,
      ];
    });
    const coverageDetails = node('details');
    coverageDetails.append(
      node('summary', 'Coverage and evidence limits'),
      node(
        'p',
        'At most 10 applications and 5 environments per application are included. Reports may omit components; this is not a security or recovery guarantee.',
      ),
      node(
        'p',
        'Open finding counts are shown snapshots, which can repeat across imports. Latest shown reports use completion time within the bounded returned history.',
      ),
    );
    return [
      ...header(
        'Security overview',
        'Reported evidence only. No scan, finding decision or restore report is independently verified.',
        applications,
      ),
      button('Refresh overview', refresh(securityOverview)),
      panel(
        node('h2', 'Coverage'),
        node('p', `${appItems.length} applications and ${scopes.length} environments reviewed.`),
        ...(partial
          ? [
              node(
                'p',
                'Coverage is partial: inventory, evidence or report availability is incomplete. Open individual applications for further records.',
              ),
            ]
          : []),
        coverageDetails,
      ),
      panel(
        node('h2', 'Environment reports'),
        rows.length
          ? table(
              [
                'Application / environment',
                'Inventory state',
                'Open finding snapshots',
                'Latest shown scan',
                'Latest shown restore',
                '',
              ],
              rows,
            )
          : empty(
              'No environments in the reviewed inventory. Add an environment to begin reporting.',
            ),
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
  async function posturePage(appId, envId) {
    const path = `${base}/${enc(appId)}/environments/${enc(envId)}`;
    const n = generation;
    let view;
    try {
      view = await ui.api(`${path}/security`);
    } catch (error) {
      if (error.status !== 404) throw error;
      return [
        ...header(
          'Security & recovery',
          'Security reporting is not enabled for this workspace.',
          () => environment(appId, envId),
        ),
      ];
    }
    const [components, app, env, members] = await Promise.all([
      list(`${path}/components`),
      ui.api(`${base}/${enc(appId)}`),
      ui.api(path),
      ui.api(`${ui.orgPath()}/members`),
    ]);
    if (!current(n)) return [];
    const reload = () => posturePage(appId, envId);
    const writable =
      ['owner', 'admin'].includes(ui.role) && app.state === 'active' && env.state === 'active';
    const label = (id) => components.find((c) => c.id === id)?.code || id;
    const assignees = [
      ['', 'Unassigned'],
      ...members.items.map((m) => [m.user_id, m.email || m.user_id]),
    ];
    const componentOptions = components
      .filter((c) => c.state === 'active')
      .map((c) => [c.id, c.code]);
    const scans = panel(
      node('h2', 'Imported scan reports'),
      node(
        'p',
        'Administrator reports. Source authenticity has not been independently verified. A completed scan is not a guarantee of security.',
      ),
    );
    scans.append(
      view.scans.items.length
        ? table(
            ['Component', 'Source / run', 'Result', 'Findings', 'Completed', 'Freshness'],
            view.scans.items.map((r) => [
              label(r.component_id),
              `${r.source} / ${r.run_id}`,
              r.outcome,
              r.finding_count,
              when(r.completed_at),
              r.freshness,
            ]),
          )
        : empty('No scan reports imported.'),
    );
    if (view.scans.truncated) scans.append(node('p', 'Only the latest 25 scan reports are shown.'));
    if (writable && componentOptions.length) {
      const details = node('details');
      details.append(node('summary', 'Import a normalized GitHub scan'));
      const select = node('select');
      select.setAttribute('aria-label', 'Scan component');
      for (const [value, text] of componentOptions) {
        const option = node('option', text);
        option.value = value;
        select.append(option);
      }
      const file = node('input');
      file.type = 'file';
      file.accept = '.json,application/json';
      file.setAttribute('aria-label', 'Normalized scan JSON');
      details.append(
        node(
          'p',
          'Use tools/normalize-security-export.ts to remove secret values, paths and provider payloads before selecting a JSON file.',
        ),
        select,
        file,
        button('Import scan', async () => {
          const selected = file.files?.[0];
          if (!selected || selected.size > 131072)
            throw new Error('Select a normalized JSON file no larger than 128 KiB.');
          let input;
          try {
            input = JSON.parse(await selected.text());
          } catch {
            throw new Error('The selected file is not valid normalized JSON.');
          }
          file.value = '';
          if (!current(n)) return;
          await ui.api(`${path}/security/scans`, 'POST', {
            ...input,
            component_id: select.value,
            reason: 'initial_setup',
          });
          if (current(n)) await show(reload);
        }),
      );
      scans.append(details);
    }
    const findings = panel(
      node('h2', 'Security findings'),
      node(
        'p',
        'Critical and unresolved findings appear first. Resolution and accepted risk record an administrator decision; they do not verify a fix. Each scan retains its own finding snapshots.',
      ),
    );
    findings.append(
      view.findings.items.length
        ? table(
            ['Component', 'Severity', 'Advisory / fingerprint', 'State', 'Responder', 'Actions'],
            view.findings.items.map((r) => {
              const edit = node('details');
              edit.append(node('summary', 'Edit finding'));
              const editable =
                writable && components.some((c) => c.id === r.component_id && c.state === 'active');
              if (editable)
                edit.append(
                  form(
                    [
                      {
                        name: 'state',
                        label: 'Finding state',
                        value: r.state,
                        options: choices(['open', 'acknowledged', 'resolved', 'accepted_risk']),
                      },
                      {
                        name: 'assignee_user_id',
                        label: 'Finding responder',
                        value: r.assignee_user_id || '',
                        options: assignees,
                        optional: true,
                      },
                    ],
                    'Save finding',
                    async (data, visit) => {
                      await ui.api(`${path}/security/findings/${enc(r.id)}`, 'PATCH', {
                        ...data,
                        assignee_user_id: data.assignee_user_id || null,
                        expected_version: r.version,
                        reason: 'security_response',
                      });
                      if (current(visit)) await show(reload);
                    },
                  ),
                );
              return [
                label(r.component_id),
                r.severity,
                r.advisory_id || r.fingerprint.slice(0, 12),
                r.state,
                members.items.find((m) => m.user_id === r.assignee_user_id)?.email ||
                  r.assignee_user_id ||
                  'Unassigned',
                editable ? edit : 'Read only',
              ];
            }),
          )
        : empty('No findings imported.'),
    );
    if (view.findings.truncated)
      findings.append(node('p', 'Only the first 200 prioritized findings are shown.'));
    const recovery = panel(
      node('h2', 'Recovery evidence'),
      node(
        'p',
        'Reported backups, restores and rollbacks are distinct. These records have not been independently verified; importing a backup never proves a successful restore.',
      ),
    );
    recovery.append(
      view.recovery.items.length
        ? table(
            [
              'Component',
              'Type / result',
              'Checks',
              'Reported RPO / RTO',
              'Targets',
              'Completed / freshness',
            ],
            view.recovery.items.map((r) => [
              label(r.component_id),
              `${r.kind} / ${r.outcome}`,
              `Integrity: ${r.integrity_check}; application: ${r.application_check}; audit: ${r.audit_check}`,
              `${r.rpo_seconds ?? '—'}s / ${r.rto_seconds ?? '—'}s`,
              r.target_met === null
                ? 'Not assessed'
                : r.target_met
                  ? 'Reported targets met'
                  : 'Targets not met',
              `${when(r.completed_at)} / ${r.freshness}`,
            ]),
          )
        : empty('No recovery reports recorded.'),
    );
    if (view.recovery.truncated)
      recovery.append(node('p', 'Only the latest 25 recovery reports are shown.'));
    if (writable && componentOptions.length) {
      const details = node('details');
      details.append(
        node('summary', 'Record a recovery report'),
        form(
          [
            { name: 'component_id', label: 'Recovery component', options: componentOptions },
            {
              name: 'kind',
              label: 'Recovery type',
              options: choices(['backup', 'restore', 'rollback']),
            },
            {
              name: 'outcome',
              label: 'Reported outcome',
              options: choices(['succeeded', 'failed']),
            },
            {
              name: 'started_at',
              label: 'Started at (UTC)',
              value: '',
            },
            { name: 'completed_at', label: 'Completed at (UTC)' },
            { name: 'recovery_point_at', label: 'Recovered data timestamp (UTC)', optional: true },
            ...['integrity_check', 'application_check', 'audit_check'].map((name) => ({
              name,
              label: name.replaceAll('_', ' '),
              options: choices(['not_run', 'passed', 'failed']),
            })),
            {
              name: 'artifact_digest',
              label: 'Evidence artifact SHA-256',
              pattern: '[a-f0-9]{64}',
              max: 64,
            },
            {
              name: 'target_rpo_seconds',
              label: 'Target data loss in seconds',
              type: 'number',
              value: '300',
              max: 604800,
            },
            {
              name: 'target_rto_seconds',
              label: 'Target recovery time in seconds',
              type: 'number',
              value: '7200',
              min: 1,
              max: 604800,
            },
          ],
          'Record report',
          async (data, visit) => {
            await ui.api(`${path}/security/recovery`, 'POST', {
              ...data,
              recovery_point_at: data.recovery_point_at || null,
              reason: 'initial_setup',
            });
            if (current(visit)) await show(reload);
          },
        ),
      );
      recovery.append(details);
    }
    return [
      ...header(
        'Security & recovery',
        `${app.code} / ${env.code} · assessed ${when(view.assessed_at)}`,
        () => environment(appId, envId),
      ),
      button('Refresh evidence', refresh(reload)),
      scans,
      findings,
      recovery,
    ];
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
      button(
        'Security & recovery',
        refresh(() => posturePage(appId, id)),
      ),
      await healthPanel(path),
      await incidentsPanel(path, components, writable, reload),
      await automationPanel(
        path,
        components,
        writable && ['owner', 'admin'].includes(ui.role),
        reload,
      ),
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
  function openResponseGuide(code, componentCode) {
    const guide = responseGuide(code);
    if (!guide) return;
    const steps = node('ol');
    for (const step of guide.steps) steps.append(node('li', step));
    ui.modal(
      node('h2', guide.title),
      panel(
        node('p', `Affected component: ${componentCode}`),
        node(
          'p',
          'This guide makes no changes. Infrastructure actions require the approved provider workflow. Assign and acknowledge incidents with Manage incident.',
        ),
        steps,
        node('h3', 'Verify recovery'),
        node('p', guide.recovery),
        node('h3', 'Escalate'),
        node('p', guide.escalation),
      ),
    );
  }
  async function automationPanel(path, components, writable, reload) {
    const card = panel(node('h2', 'Automatic alerts'));
    let rules, notifications;
    try {
      rules = (await ui.api(`${path}/rules`)).items;
      notifications = (await ui.api(`${path}/notifications`)).items;
    } catch (e) {
      card.append(
        node(
          'p',
          e.status === 404
            ? 'Automatic alerts are not enabled in this workspace.'
            : 'Automatic alert state could not be loaded.',
        ),
      );
      return card;
    }
    card.append(
      node(
        'p',
        'Rules evaluate committed backend observations. Recovery requires fresh healthy evidence. Notifications appear here for the person who created the rule.',
      ),
    );
    card.append(
      rules.length
        ? table(
            ['Component', 'Rule', 'Observation', 'Maintenance', 'Actions'],
            rules.map((r) => [
              components.find((c) => c.id === r.component_id)?.code || r.component_id,
              `${r.kind === 'heartbeat' ? 'Heartbeat' : r.event_type} · ${r.threshold} / ${r.window_seconds}s · ${r.severity}`,
              `${r.enabled ? r.observation : 'Disabled'}${r.kind === 'event_count' ? ` (${r.observed_count})` : ''}`,
              when(r.maintenance_until),
              (() => {
                const actions = node('div', undefined, 'actions');
                if (responseGuide(r.runbook))
                  actions.append(
                    button('Open response guide', () =>
                      openResponseGuide(
                        r.runbook,
                        components.find((c) => c.id === r.component_id)?.code || r.component_id,
                      ),
                    ),
                  );
                if (!writable) {
                  actions.append(node('span', 'Read only'));
                  return actions;
                }
                const change = async (enabled, until) => {
                  const n = generation;
                  for (let attempt = 0; attempt < 2; attempt++) {
                    const latest = (await ui.api(`${path}/rules`)).items.find(
                      (item) => item.id === r.id,
                    );
                    if (!current(n)) return;
                    if (
                      !latest ||
                      latest.enabled !== r.enabled ||
                      latest.maintenance_until !== r.maintenance_until
                    )
                      throw new Error('Rule settings changed. Refresh this view and try again.');
                    try {
                      await ui.api(`${path}/rules/${enc(r.id)}`, 'PATCH', {
                        expected_version: latest.version,
                        enabled,
                        maintenance_until: until,
                        reason: 'maintenance',
                      });
                      break;
                    } catch (error) {
                      if (error.status !== 409 || attempt === 1) throw error;
                    }
                  }
                  if (current(n)) await show(reload);
                };
                actions.append(
                  button(r.enabled ? 'Disable rule' : 'Enable rule', () =>
                    change(
                      !r.enabled,
                      r.maintenance_until && new Date(r.maintenance_until) > new Date()
                        ? r.maintenance_until
                        : null,
                    ),
                  ),
                  button(
                    r.maintenance_until && new Date(r.maintenance_until) > new Date()
                      ? 'End maintenance'
                      : 'Mute for 1 hour',
                    () =>
                      change(
                        r.enabled,
                        r.maintenance_until && new Date(r.maintenance_until) > new Date()
                          ? null
                          : new Date(Date.now() + 3600000).toISOString(),
                      ),
                  ),
                );
                return actions;
              })(),
            ]),
          )
        : empty('No automatic rules configured.'),
    );
    if (writable) {
      card.append(
        button('Evaluate rules now', async () => {
          const n = generation;
          await ui.api(`${path}/rules/evaluate`, 'POST', {});
          if (current(n)) await show(reload);
        }),
      );
      const setup = node('details', undefined, 'compact-disclosure');
      setup.append(node('summary', 'Create an automatic rule'));
      setup.append(
        form(
          [
            {
              name: 'component_id',
              label: 'Alert component',
              options: components.filter((c) => c.state === 'active').map((c) => [c.id, c.code]),
            },
            { name: 'kind', label: 'Condition', options: choices(['heartbeat', 'event_count']) },
            {
              name: 'event_type',
              label: 'Failure event (event count only)',
              options: choices([
                'conversion.failed',
                'upload.failed',
                'scanner.unavailable',
                'malware.detected',
                'email.delivery_failed',
              ]),
            },
            {
              name: 'threshold',
              label: 'Failure count (heartbeat: 1)',
              type: 'number',
              value: '1',
            },
            {
              name: 'window_seconds',
              label: 'Evaluation window in seconds (60–3600)',
              type: 'number',
              value: '60',
            },
            {
              name: 'severity',
              label: 'Alert severity',
              options: choices(['informational', 'warning', 'critical']),
            },
            {
              name: 'runbook',
              label: 'Response guide',
              options: choices([
                'investigate_component',
                'check_scanner',
                'check_converter',
                'check_storage',
                'check_email',
              ]),
            },
          ],
          'Create rule',
          async (data, n) => {
            data.event_type = data.kind === 'heartbeat' ? null : data.event_type;
            await ui.api(`${path}/rules`, 'POST', { ...data, reason: 'initial_setup' });
            if (current(n)) await show(reload);
          },
        ),
      );
      card.append(setup);
    }
    card.append(
      node('h3', 'Your portal notifications'),
      notifications.length
        ? table(
            ['Incident', 'Transition', 'Delivery', 'Attempts', 'Created'],
            notifications.map((n) => [
              n.incident_id,
              n.transition,
              n.state === 'delivered' ? 'Available in portal' : n.state,
              n.attempts,
              when(n.created_at),
            ]),
          )
        : empty('No portal notifications yet.'),
    );
    return card;
  }
  async function incidentsPanel(path, components, openAllowed, reload) {
    const wrap = panel(
      node('h2', 'Incidents'),
      node(
        'p',
        'Incident triage. Opening or resolving an incident does not change reported health. Automatic rule settings and portal notifications appear below.',
      ),
    );
    let page;
    try {
      page = await ui.api(`${path}/incidents?limit=25`);
    } catch (e) {
      if (e.status === 401) throw e;
      wrap.append(
        empty(
          e.status === 404
            ? 'Incident management is not enabled for this workspace.'
            : 'Incident records are currently unavailable.',
        ),
      );
      return wrap;
    }
    const members = (await ui.api(`${ui.orgPath()}/members`)).items;
    const names = new Map(
      members.map((m) => [m.user_id, m.user_id === ui.userId ? 'You' : m.email || m.user_id]),
    );
    const codes = new Map(components.map((c) => [c.id, c.code]));
    const rows = [...page.items];
    let after = page.next_after;
    const content = node('div');
    function manage(row) {
      const fixedReason = (value) => ({
        name: 'reason',
        label: 'Reason',
        options: choices([value]),
      });
      const actionForm = (action, why, label, fields = []) =>
        form([...fields, fixedReason(why)], label, async (data, n) => {
          await ui.api(`${path}/incidents/${enc(row.id)}/${action}`, 'POST', {
            ...data,
            expected_version: row.version,
            ...(action === 'assign' ? { assignee_user_id: data.assignee_user_id || null } : {}),
          });
          if (current(n)) await show(reload);
        });
      ui.modal(
        node('h2', 'Manage incident'),
        panel(
          node(
            'p',
            `${codes.get(row.component_id) || row.component_id} · ${row.severity} · ${row.state} · version ${row.version}`,
          ),
          ...(row.state === 'open'
            ? [actionForm('acknowledge', 'incident_ack', 'Acknowledge incident')]
            : []),
          actionForm('assign', 'assignment', 'Assign incident', [
            {
              name: 'assignee_user_id',
              label: 'Assigned responder',
              optional: true,
              value: row.assignee_user_id ?? '',
              options: [
                ['', 'Unassigned'],
                ...members.map((m) => [m.user_id, names.get(m.user_id)]),
              ],
            },
          ]),
          actionForm('resolve', 'incident_resolution', 'Resolve incident'),
        ),
      );
    }
    const more = button('Load more incidents', async () => {
      const n = generation;
      const next = await ui.api(`${path}/incidents?limit=25&after=${enc(after)}`);
      if (!current(n)) return;
      rows.push(...next.items);
      after = next.next_after;
      render();
    });
    const filters = node('div');
    function filter(label, values) {
      const select = node('select');
      select.setAttribute('aria-label', label);
      const field = node('label', label);
      for (const [value, text] of [['', 'All'], ...choices(values)]) {
        const option = node('option', text);
        option.value = value;
        select.append(option);
      }
      field.append(select);
      filters.append(field);
      select.addEventListener('change', render);
      return select;
    }
    const stateFilter = filter('Filter incident state', ['open', 'acknowledged', 'resolved']);
    const severityFilter = filter('Filter incident severity', [
      'informational',
      'warning',
      'critical',
    ]);
    const summary = node('p');
    summary.setAttribute('role', 'status');
    filters.append(
      button('Clear incident filters', () => {
        stateFilter.value = '';
        severityFilter.value = '';
        render();
      }),
      summary,
    );
    function render() {
      more.hidden = !after;
      const matching = rows.filter(
        (r) =>
          (!stateFilter.value || r.state === stateFilter.value) &&
          (!severityFilter.value || r.severity === severityFilter.value),
      );
      summary.textContent = `${matching.length} matching of ${rows.length} loaded incidents.${after ? ' More records remain; load more to include them.' : ' All available incident records are loaded.'}`;
      content.replaceChildren(
        matching.length
          ? table(
              ['Component', 'Severity', 'State', 'Assigned responder', 'Opened', 'Actions'],
              matching.map((r) => [
                codes.get(r.component_id) || r.component_id,
                r.severity,
                r.state,
                r.assignee_user_id
                  ? names.get(r.assignee_user_id) || 'Former member'
                  : 'Unassigned',
                when(r.created_at),
                r.state === 'resolved' ? 'Resolved' : button('Manage incident', () => manage(r)),
              ]),
            )
          : empty(
              rows.length ? 'No loaded incidents match these filters.' : 'No incidents recorded.',
            ),
        more,
      );
    }
    render();
    wrap.append(filters, content);
    const active = components.filter((c) => c.state === 'active');
    if (openAllowed && active.length)
      wrap.append(
        form(
          [
            {
              name: 'component_id',
              label: 'Affected component',
              options: active.map((c) => [c.id, c.code]),
            },
            {
              name: 'severity',
              label: 'Incident severity',
              options: choices(['informational', 'warning', 'critical']),
            },
            { name: 'reason', label: 'Reason', options: choices(['security_response']) },
          ],
          'Open incident',
          async (data, n) => {
            await ui.api(`${path}/incidents`, 'POST', data);
            if (current(n)) await show(reload);
          },
        ),
      );
    return wrap;
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
