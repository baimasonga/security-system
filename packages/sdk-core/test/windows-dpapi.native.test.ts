import { randomBytes } from 'node:crypto';
import { readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { expect, it } from 'vitest';
import { WindowsDpapiStore } from '../src/index.ts';

it.skipIf(process.platform !== 'win32')(
  'round trips protected Unicode records across instances and detects ciphertext tampering on Windows',
  async () => {
    const scope = 'native_test_' + randomBytes(12).toString('hex');
    const directory = join(process.env.LOCALAPPDATA!, 'TrustPlatform', scope);
    const store = new WindowsDpapiStore(scope);
    try {
      expect(await store.get('missing')).toBeUndefined();
      await store.set('lease', 'secret ⚑ Unicode');
      const restored = new WindowsDpapiStore(scope);
      expect(await restored.get('lease')).toBe('secret ⚑ Unicode');
      const file = join(directory, (await readdir(directory))[0]!);
      const bytes = await readFile(file);
      expect(bytes.includes(Buffer.from('secret'))).toBe(false);
      await store.set('lease', 'replacement');
      expect(await restored.get('lease')).toBe('replacement');
      await writeFile(file, Buffer.from('corrupt ciphertext'));
      await expect(restored.get('lease')).rejects.toThrow('protected storage unavailable');
      await store.delete('lease');
      expect(await restored.get('lease')).toBeUndefined();
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  },
);
