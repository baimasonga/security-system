// CI-only diagnosis using a new disposable scope and a fixed non-secret value.
// Never run with customer scopes, key material or payloads.
import { spawnSync } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import { win32 } from 'node:path';

if (process.platform !== 'win32') throw new Error('Windows diagnostic requires Windows');
const source = await readFile(
  new URL('../packages/sdk-core/src/windows-store.ts', import.meta.url),
  'utf8',
);
const start = source.indexOf('const SCRIPT = String.raw`') + 'const SCRIPT = String.raw`'.length;
const end = source.indexOf('`;', start);
if (start < 'const SCRIPT = String.raw`'.length || end < start)
  throw new Error('diagnostic script source missing');
const original = source.slice(start, end),
  anchor = "catch { [Console]::Error.Write('protected storage unavailable'); exit 1 }";
if (!original.includes(anchor)) throw new Error('diagnostic catch anchor missing');
const script = original.replace(
  anchor,
  'catch { [Console]::Error.Write(($_ | Out-String)); exit 1 }',
);
const scope = 'ci_diagnostic_' + process.pid + '_' + Date.now();
try {
  const requests: Array<{ operation: string; value?: string }> = [
    { operation: 'get' },
    { operation: 'set', value: 'fixed-non-secret-fixture ⚑' },
    { operation: 'get' },
    { operation: 'set', value: 'replacement-fixture' },
    { operation: 'get' },
    { operation: 'delete' },
    { operation: 'get' },
  ];
  for (const [index, request] of requests.entries()) {
    const result = spawnSync(
      win32.join(
        process.env.SystemRoot!,
        'System32',
        'WindowsPowerShell',
        'v1.0',
        'powershell.exe',
      ),
      [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64'),
      ],
      {
        windowsHide: true,
        input: JSON.stringify({ scope, key: 'diagnostic', ...request }),
        encoding: 'utf8',
        timeout: 15_000,
        maxBuffer: 64 * 1024,
      },
    );
    if (result.status !== 0) {
      // Only this disposable fixture is processed. Escape GitHub workflow-command delimiters.
      const error = String(
        result.stderr || result.error?.message || 'Unknown Windows diagnostic failure',
      )
        .slice(0, 12000)
        .replaceAll('%', '%25')
        .replaceAll('\r', '%0D')
        .replaceAll('\n', '%0A');
      console.error(
        `::error title=Windows synthetic-storage diagnosis (${index} ${request.operation})::` +
          error,
      );
      process.exitCode = 1;
      break;
    }
    console.log(`Synthetic Windows storage step ${index} ${request.operation} passed.`);
  }
} finally {
  await rm(win32.join(process.env.LOCALAPPDATA!, 'TrustPlatform', scope), {
    recursive: true,
    force: true,
  });
}
