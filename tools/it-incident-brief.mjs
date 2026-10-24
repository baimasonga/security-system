// Operator-run evidence collection. No model, credentials, database access or remediation.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkAvailability } from './check-warrior-availability.mjs';
import { checkRokelaAvailability } from './check-rokela-availability.mjs';

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
  }
}
