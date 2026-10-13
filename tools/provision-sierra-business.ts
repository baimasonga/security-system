import { parseArgs } from 'node:util';
import { CatalogSetupError, catalogHttpRequest, provisionSierraCatalog } from './sierra-catalog.ts';

try {
  const { values } = parseArgs({
    options: {
      'plan-code': { type: 'string' },
      tier: { type: 'string' },
      'device-limit': { type: 'string' },
      reason: { type: 'string' },
      apply: { type: 'boolean', default: false },
      'allow-local': { type: 'boolean', default: false },
    },
  });
  if (!values['plan-code'] || !values.tier || !values['device-limit'] || !values.reason)
    throw new CatalogSetupError(
      'Required: --plan-code, --tier, --device-limit and --reason. Preview is default; --apply creates missing catalog entries.',
    );
  const request = catalogHttpRequest(
    process.env.TRUST_API_ORIGIN ?? '',
    process.env.TRUST_OPERATOR_TOKEN ?? '',
    values['allow-local'],
  );
  const result = await provisionSierraCatalog(request, {
    planCode: values['plan-code'],
    tier: values.tier,
    deviceLimit: Number(values['device-limit']),
    reason: values.reason,
    apply: values.apply,
  });
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  // Never print untrusted API bodies, command arguments, credentials or network error details.
  const safe =
    error instanceof CatalogSetupError
      ? error.message
      : 'catalog setup failed; check required arguments and settings';
  console.error(safe);
  process.exitCode = 1;
}
