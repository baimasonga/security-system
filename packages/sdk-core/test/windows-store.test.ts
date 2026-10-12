import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
const transport = vi.hoisted(() => ({
  output: '{}',
  code: 0,
  request: '',
  arguments: [] as string[],
  executable: '',
}));
vi.mock('node:child_process', () => ({
  spawn: (executable: string, args: string[]) => {
    transport.executable = executable;
    transport.arguments = args;
    const child = Object.assign(new EventEmitter(), {
      stdin: new PassThrough(),
      stdout: new PassThrough(),
      stderr: new PassThrough(),
      kill: () => true,
    });
    transport.request = '';
    child.stdin.on('data', (c) => {
      transport.request += String(c);
    });
    child.stdin.on('finish', () => {
      child.stdout.write(transport.output);
      child.stdout.end();
      child.emit('close', transport.code);
    });
    return child;
  },
}));
import { WindowsDpapiStore } from '../src/index.ts';
const descriptor = Object.getOwnPropertyDescriptor(process, 'platform')!;
beforeEach(() => {
  Object.defineProperty(process, 'platform', { value: 'win32' });
  vi.stubEnv('SystemRoot', 'C:\\Windows');
  transport.output = '{}';
  transport.code = 0;
  transport.arguments = [];
});
afterEach(() => {
  Object.defineProperty(process, 'platform', descriptor);
  vi.unstubAllEnvs();
});
it('passes secrets only on stdin to a fixed system executable and preserves Unicode', async () => {
  const store = new WindowsDpapiStore('editor');
  await store.set('device_key', 'private ⚑ value');
  expect(transport.executable).toBe(
    'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  );
  expect(transport.arguments.join(' ')).not.toContain('private');
  expect(JSON.parse(transport.request)).toEqual({
    scope: 'editor',
    operation: 'set',
    key: 'device_key',
    value: 'private ⚑ value',
  });
  transport.output = JSON.stringify({ value: 'private ⚑ value' });
  expect(await store.get('device_key')).toBe('private ⚑ value');
});
it('reports a missing key without generating or replacing it', async () => {
  expect(await new WindowsDpapiStore('editor').get('device_key')).toBeUndefined();
  expect(JSON.parse(transport.request).operation).toBe('get');
});
it.each([
  { output: 'private provider exception', code: 1 },
  { output: 'not json', code: 0 },
  { output: '{"value":42}', code: 0 },
  { output: '{"value":"secret","other":true}', code: 0 },
])('fails closed with sanitized errors', async (o) => {
  Object.assign(transport, o);
  await expect(new WindowsDpapiStore('editor').get('device_key')).rejects.toThrow(
    'protected storage unavailable',
  );
});
it('rejects other platforms, traversal scopes, and oversized values', async () => {
  expect(() => new WindowsDpapiStore('../other')).toThrow();
  await expect(
    new WindowsDpapiStore('editor').set('lease', 'a'.repeat(1024 * 1024 + 1)),
  ).rejects.toThrow('invalid protected storage');
  Object.defineProperty(process, 'platform', { value: 'linux' });
  await expect(new WindowsDpapiStore('editor').get('lease')).rejects.toThrow('requires Windows');
  expect(transport.arguments).toEqual([]);
});
