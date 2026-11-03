// Operator-only presentation over the existing signed-release API. No signing or artifact fetching.
export function releaseConsole({ api, node, panel, fieldsForm, table, current }) {
  const reason = { name: 'reason', label: 'Release change reason', min: 3, max: 500 };
  const product = { name: 'product_id', label: 'Release product ID' };
  const target = [
    { name: 'platform', label: 'Release platform', value: 'windows-x64' },
    { name: 'channel', label: 'Release channel', value: 'stable' },
  ];
  const receipt = { name: 'request_id', label: 'Reservation request UUID' };
  const output = node('div');
  output.setAttribute('aria-live', 'polite');
  const path = (id) => `/v1/admin/products/${encodeURIComponent(id)}/update-registry`;
  const print = (value) => {
    if (current()) output.replaceChildren(node('pre', JSON.stringify(value, null, 2)));
  };
  const query = (data) => new URLSearchParams({ platform: data.platform, channel: data.channel });
  const action = node('select');
  action.setAttribute('aria-label', 'Release operation');
  const forms = [];
  const add = (name, fields, handler) => {
    const option = node('option', name);
    option.value = String(forms.length);
    action.append(option);
    const form = fieldsForm(fields, name, async (data, element) => {
      if (!current()) return;
      output.replaceChildren();
      action.disabled = true;
      try {
        await handler(data, element);
      } finally {
        action.disabled = false;
      }
    });
    form.hidden = forms.length !== 0;
    forms.push(form);
  };
  add('Read update registry', [product], async (data) => {
    const registry = await api(path(data.product_id));
    const rows = await Promise.all(
      registry.targets.map(async (t) => {
        try {
          const params = query(t);
          params.set('limit', '1');
          const history = await api(`${path(data.product_id)}/releases?${params}`);
          const latest = history.items[0];
          return [
            t.platform,
            t.channel,
            t.reserved_sequence,
            latest?.sequence ?? 'None recorded',
            latest
              ? latest.manifest.paused
                ? 'Signed pause'
                : 'Signed release'
              : 'No publication recorded',
          ];
        } catch {
          return [t.platform, t.channel, t.reserved_sequence, 'Unknown', 'History unavailable'];
        }
      }),
    );
    if (!current()) return;
    output.replaceChildren(
      node('h3', `Registered update targets · ${registry.product}`),
      node(
        'p',
        `Public root version ${registry.root.version}. Root expires ${new Date(registry.root.expires * 1000).toISOString()}. Reserved sequences do not establish publication or installation.`,
      ),
      table(
        [
          'Platform',
          'Channel',
          'Reserved sequence',
          'Latest published sequence',
          'Historical signed state',
        ],
        rows,
      ),
    );
  });
  add(
    'Register public update root',
    [product, { name: 'root', label: 'Public update root (JSON)', type: 'json' }, reason],
    async ({ product_id, ...body }) => {
      print(await api(path(product_id), 'POST', body));
    },
  );
  add('Register update target', [product, ...target, reason], async ({ product_id, ...body }) => {
    print(await api(`${path(product_id)}/targets`, 'POST', body));
  });
  add(
    'Raise historical sequence floor',
    [
      product,
      ...target,
      {
        name: 'sequence',
        label: 'Historical sequence floor',
        type: 'number',
        min: 1,
        max: Number.MAX_SAFE_INTEGER,
      },
      reason,
    ],
    async ({ product_id, ...body }) => {
      if (
        !confirm(
          'Attest this sequence floor from trusted build records? It cannot be lowered and is unavailable after the first publication.',
        )
      )
        return;
      print(await api(`${path(product_id)}/sequence-floor`, 'POST', body));
    },
  );
  add(
    'Reserve release sequence',
    [product, ...target, receipt, reason],
    async ({ product_id, ...body }) => {
      // Keep all inputs after success/failure. An uncertain request must retry its exact UUID and target.
      if (
        !confirm(
          'Reserve this sequence? Save the UUID and receipt. A new reservation abandons older unpublished work for this target.',
        )
      )
        return;
      print(await api(`${path(product_id)}/reservations`, 'POST', body));
    },
  );
  add(
    'Publish signed release or pause',
    [
      product,
      ...target,
      receipt,
      { name: 'envelope', label: 'Externally signed envelope (JSON)', type: 'json' },
      reason,
    ],
    async ({ product_id, ...body }) => {
      if (
        !confirm(
          'Publish this externally signed envelope? The server must verify it. Withdrawal requires a higher-sequence signed pause; history cannot be edited.',
        )
      )
        return;
      const result = await api(`${path(product_id)}/releases`, 'POST', body);
      if (!current()) return;
      output.replaceChildren(
        node('h3', result.manifest.paused ? 'Signed pause recorded' : 'Signed release recorded'),
        node(
          'p',
          'Signature acceptance is not proof that artifacts are available or software was installed. Exact retries return the original record; they do not replace a newer feed.',
        ),
        node('pre', JSON.stringify(result, null, 2)),
      );
    },
  );
  add(
    'Read release history',
    [
      product,
      ...target,
      {
        name: 'before',
        label: 'Before sequence (optional)',
        type: 'number',
        min: 1,
        optional: true,
      },
    ],
    async (data) => {
      const params = query(data);
      params.set('limit', '20');
      if (data.before !== undefined) params.set('before', String(data.before));
      const result = await api(`${path(data.product_id)}/releases?${params}`);
      if (!current()) return;
      output.replaceChildren(
        node('h3', 'Immutable release history'),
        node(
          'p',
          'At most 20 records are shown. Use Before sequence with the oldest shown sequence for the next page. History may contain expired or superseded metadata.',
        ),
        table(
          ['Sequence', 'Version', 'Signed state', 'Expires', 'Published'],
          result.items.map((r) => [
            r.sequence,
            r.manifest.version,
            r.manifest.paused ? 'Paused' : 'Release',
            new Date(r.manifest.expires * 1000).toISOString(),
            r.published_at,
          ]),
        ),
      );
    },
  );
  add('Read current signed feed', [product, ...target], async (data) => {
    const params = query(data);
    // Use fetch without an account token for this intentionally public endpoint.
    const response = await fetch(
      `/v1/updates/${encodeURIComponent(data.product_id)}/current?${params}`,
      { cache: 'no-store' },
    );
    if (!current()) return;
    if (!response.ok) {
      output.replaceChildren(
        node(
          'p',
          'No current feed established. Metadata may be absent, expired, disabled or unavailable. This does not prove support or revocation.',
        ),
      );
      return;
    }
    print(await response.json());
  });
  action.addEventListener('change', () => {
    forms.forEach((f, i) => {
      f.hidden = action.value !== String(i);
    });
    output.replaceChildren();
  });
  const label = node('label', 'Choose a release operation');
  label.append(action);
  const availability = node('p', 'Checking release management availability…');
  availability.setAttribute('aria-live', 'polite');
  let statusVersion = 0;
  const refreshStatus = async () => {
    const version = ++statusVersion;
    availability.textContent = 'Checking release management availability…';
    output.replaceChildren();
    try {
      const status = await api('/v1/admin/update-catalog/status');
      if (!current() || version !== statusVersion) return;
      availability.textContent =
        status.enabled === true
          ? 'Release management is enabled on this deployment.'
          : status.enabled === false
            ? 'Release management is not enabled on this deployment. Ask the deployment owner to enable it.'
            : 'Release management availability could not be confirmed.';
    } catch {
      if (current() && version === statusVersion)
        availability.textContent = 'Release management availability could not be confirmed.';
    }
  };
  const refresh = node('button', 'Refresh release availability');
  refresh.type = 'button';
  refresh.addEventListener('click', refreshStatus);
  void refreshStatus();
  return panel(
    node('h2', 'Product releases'),
    availability,
    refresh,
    node(
      'p',
      'These controls manage signed release metadata. They do not install updates or confirm that desktop installations support automatic updates.',
    ),
    node(
      'p',
      'Manage each product/platform/channel independently. Catalog access requires UPDATE_CATALOG_ENABLED on the server. A 404 can mean the feature or registry is unavailable; it does not establish support.',
    ),
    node(
      'p',
      'Paste public roots and signed envelopes only. Never paste signing private keys. Sign outside Warrior. Save reservation UUIDs and receipts in your release records before continuing; this page does not persist them. Retrying after an uncertain response requires the same UUID, target and exact envelope. Do not reserve a new sequence to retry.',
    ),
    node(
      'p',
      'Before first publication, reconcile historical sequence floors from trusted builds. To withdraw, reserve a higher sequence and publish an externally signed paused manifest. To resume or renew expiry, publish another higher sequence. No percentage rollout or native installation is performed here.',
    ),
    label,
    ...forms,
    output,
  );
}
