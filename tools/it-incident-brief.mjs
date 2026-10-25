// Operator-run evidence collection. No model, credentials, database access or remediation.
import { resolve } from 'node:path';
import { appendFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { checkAvailability } from './check-warrior-availability.mjs';
import { checkRokelaAvailability } from './check-rokela-availability.mjs';

export function renderIncidentSummary(brief) {
  const checks = [
    ['warrior', 'liveness', 'Warrior liveness'],
    ['warrior', 'readiness', 'Warrior readiness'],
    ['rokela-pdf', 'health', 'Rokela PDF health'],
    ['rokela-pdf', 'signin', 'Rokela PDF sign-in page'],
  ];
  const timestamp = (value) =>
    typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
      ? value
      : 'Unavailable';
  const rows = checks.map(([application, check, label]) => {
    const matches = (brief.observations ?? []).filter(
      (entry) => entry.application === application && entry.check === check,
    );
    const outcome = matches.length === 1 ? matches[0].outcome : undefined;
    return `| ${label} | ${outcome === 'passed' ? 'Passed' : outcome === 'failed' ? 'Failed' : 'Unknown'} |`;
  });
  return [
    '## IT incident brief',
    '',
    `Observation window (UTC): ${timestamp(brief.started_at)} → ${timestamp(brief.completed_at)}`,
    '',
    '| Public check | Result |',
    '| --- | --- |',
    ...rows,
    '',
    '**Root cause: not established.** A failed check can also reflect observer network failure.',
    '',
    'These checks do not verify login/MFA, conversion, scanning or email inbox delivery.',
    'Deployment correlation, fresh component reports, independent audit anchoring and production restore acceptance need separate evidence.',
    '',
    'Next: compare deployment and incident times, inspect scoped sanitized logs, and verify the affected user workflow.',
    '',
  ].join('\n');
}

export async function collectIncidentBrief(request = globalThis.fetch) {
  const started_at = new Date().toISOString();
  const [warrior, pdf] = await Promise.all([
    checkAvailability(request),
    checkRokelaAvailability(request),
  ]);
  const observations = [
    ...warrior.map(({ check, outcome }) => ({ application: 'warrior', check, outcome })),
    ...pdf.map(({ check, outcome }) => ({ application: 'rokela-pdf', check, outcome })),
  ];
  return {
    version: 1,
    observer: 'operator_run_public_http',
    started_at,
    completed_at: new Date().toISOString(),
    observations,
    root_cause: 'not_established',
    evidence_gaps: [
      'deployment_correlation',
      'component_heartbeat_freshness',
      'authenticated_workflows',
      'incident_email_inbox_delivery',
      'independent_audit_witness',
      'production_restore_acceptance',
    ],
    next_steps: observations.some((r) => r.outcome !== 'passed')
      ? [
          'check_observer_network_then_service',
          'compare_deployment_and_incident_times',
          'inspect_scoped_sanitized_logs',
        ]
      : ['review_component_heartbeat_freshness', 'verify_incident_delivery_and_recovery'],
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) {
    console.error('Usage: node tools/it-incident-brief.mjs (no arguments)');
    process.exitCode = 2;
  } else {
    const brief = await collectIncidentBrief();
    console.log(JSON.stringify(brief, null, 2));
    process.exitCode = brief.observations.every((r) => r.outcome === 'passed') ? 0 : 1;
    if (process.env.GITHUB_STEP_SUMMARY) {
      try {
        await appendFile(process.env.GITHUB_STEP_SUMMARY, renderIncidentSummary(brief));
      } catch {
        console.error('Unable to write incident summary. JSON evidence is available above.');
        process.exitCode = 1;
      }
    }
  }
}
