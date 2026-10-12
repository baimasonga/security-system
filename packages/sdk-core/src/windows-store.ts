import { spawn } from 'node:child_process';
import { win32 } from 'node:path';
import type { SecureStore } from './device-key.ts';

// Static script only: secret data travels on stdin, never in process arguments or the shell.
const SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
try {
  Add-Type -AssemblyName System.Security
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $scope = [string]$request.scope
  $key = [string]$request.key
  if ($scope -notmatch '^[A-Za-z0-9_-]{1,64}$' -or $key.Length -lt 1 -or $key.Length -gt 256) { throw 'invalid input' }
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $base = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'TrustPlatform'
  $directory = Join-Path $base $scope
  [IO.Directory]::CreateDirectory($directory) | Out-Null
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  $acl.AddAccessRule($rule)
  [IO.Directory]::SetAccessControl($directory, $acl)
  $sha = [Security.Cryptography.SHA256]::Create()
  $entropy = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes('trust-platform/store/v1/' + $scope))
  $name = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key)))).Replace('-','').ToLowerInvariant()
  $path = Join-Path $directory ($name + '.dpapi')
  if ($request.operation -eq 'get') {
    if (-not [IO.File]::Exists($path)) { [Console]::Out.Write('{}'); exit 0 }
    $ciphertext = [IO.File]::ReadAllBytes($path)
    if ($ciphertext.Length -gt 2097152) { throw 'oversized record' }
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($ciphertext, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $record = [Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json
    if ($record.scope -cne $scope -or $record.key -cne $key) { throw 'record binding' }
    [Console]::Out.Write((@{ value = [string]$record.value } | ConvertTo-Json -Compress))
  } elseif ($request.operation -eq 'set') {
    $plain = [Text.Encoding]::UTF8.GetBytes((@{ scope=$scope; key=$key; value=[string]$request.value } | ConvertTo-Json -Compress))
    $ciphertext = [Security.Cryptography.ProtectedData]::Protect($plain, $entropy, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    $temporary = Join-Path $directory ([Guid]::NewGuid().ToString('N') + '.tmp')
    try {
      $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
      try { $stream.Write($ciphertext, 0, $ciphertext.Length); $stream.Flush($true) } finally { $stream.Dispose() }
      if ([IO.File]::Exists($path)) { [IO.File]::Replace($temporary, $path, $null) } else { [IO.File]::Move($temporary, $path) }
    } finally { if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) } }
    [Console]::Out.Write('{}')
  } elseif ($request.operation -eq 'delete') {
    [IO.File]::Delete($path); [Console]::Out.Write('{}')
  } else { throw 'invalid operation' }
} catch { [Console]::Error.Write('protected storage unavailable'); exit 1 }
`;

/** Windows CurrentUser DPAPI, not TPM attestation. Host serializes access across processes. */
export class WindowsDpapiStore implements SecureStore {
  readonly #scope: string;
  constructor(scope: string) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(scope)) throw new Error('invalid protected storage scope');
    this.#scope = scope;
  }
  async #run(
    operation: 'get' | 'set' | 'delete',
    key: string,
    value?: string,
  ): Promise<string | undefined> {
    if (process.platform !== 'win32') throw new Error('Windows DPAPI requires Windows');
    if (!key || key.length > 256 || (value !== undefined && Buffer.byteLength(value) > 1024 * 1024))
      throw new Error('invalid protected storage record');
    const windows = process.env.SystemRoot;
    if (!windows || !win32.isAbsolute(windows))
      throw new Error('Windows system directory unavailable');
    const executable = win32.join(
      windows,
      'System32',
      'WindowsPowerShell',
      'v1.0',
      'powershell.exe',
    );
    return new Promise((resolve, reject) => {
      const child = spawn(
        executable,
        [
          '-NoLogo',
          '-NoProfile',
          '-NonInteractive',
          '-EncodedCommand',
          Buffer.from(SCRIPT, 'utf16le').toString('base64'),
        ],
        { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
      );
      let output = '',
        size = 0,
        failed = false;
      const fail = () => {
        if (!failed) {
          failed = true;
          child.kill();
          reject(new Error('protected storage unavailable'));
        }
      };
      const timeout = setTimeout(fail, 15_000);
      child.on('error', fail);
      child.stdin.on('error', fail);
      child.stderr.resume(); // Never forward provider exception details or secret-bearing output.
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        size += Buffer.byteLength(chunk);
        if (size > 2 * 1024 * 1024) fail();
        else output += chunk;
      });
      child.on('close', (code) => {
        clearTimeout(timeout);
        if (failed) return;
        if (code !== 0) {
          fail();
          return;
        }
        try {
          const result: unknown = JSON.parse(output);
          if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error();
          const data = result as Record<string, unknown>;
          if (
            Object.keys(data).some((k) => k !== 'value') ||
            (data.value !== undefined && typeof data.value !== 'string')
          )
            throw new Error();
          resolve(data.value as string | undefined);
        } catch {
          fail();
        }
      });
      child.stdin.end(
        JSON.stringify({
          operation,
          scope: this.#scope,
          key,
          ...(value === undefined ? {} : { value }),
        }),
      );
    });
  }
  get(key: string): Promise<string | undefined> {
    return this.#run('get', key);
  }
  async set(key: string, value: string): Promise<void> {
    await this.#run('set', key, value);
  }
  async delete(key: string): Promise<void> {
    await this.#run('delete', key);
  }
}
