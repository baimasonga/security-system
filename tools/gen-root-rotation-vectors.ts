// Public cross-language fixtures only; ephemeral private keys are never exported.
import { KeyRing, signJws } from '@trust/crypto';
const ring = new KeyRing();
const keys = Array.from({ length: 5 }, () => ring.generate('license'));
for (const k of keys) ring.activate(k.kid);
const role = (indices: number[], threshold = 1) => ({
  threshold,
  keys: indices.map((i) => ({ kid: keys[i]!.kid, jwk: keys[i]!.publicJwk })),
});
const now = 1_800_000_000;
const root = {
  schema: 1,
  version: 1,
  expires: now + 3600,
  root: role([0, 1], 2),
  release: role([4]),
  artifact_origins: ['https://updates.example'],
};
const next = { ...root, version: 2, root: role([2, 3], 2) };
const sign = (p: object, i: number, typ = 'trust-update-root+jws') =>
  signJws(p as Record<string, unknown>, { kid: keys[i]!.kid, typ }, ring.custody);
const cases: object[] = [];
const add = async (
  name: string,
  accepted: boolean,
  indices = [0, 1, 2, 3],
  candidate = next,
  typ = 'trust-update-root+jws',
  old = root,
) => {
  cases.push({
    name,
    accepted,
    root: old,
    next: candidate,
    now,
    envelope: { signatures: await Promise.all(indices.map((i) => sign(candidate, i, typ))) },
  });
};
await add('valid dual threshold rotation', true);
await add('missing new threshold', false, [0, 1, 2]);
await add('missing old threshold', false, [0, 2, 3]);
await add('duplicate old signatures', false, [0, 0, 2, 3]);
await add('duplicate new signatures', false, [0, 1, 2, 2]);
await add('release keys cannot authorize rotation', false, [4]);
await add('wrong signature purpose', false, [0, 1, 2, 3], next, 'trust-update-manifest+jws');
await add('skipped root version', false, [0, 1, 2, 3], { ...next, version: 3 });
await add('replayed root version', false, [0, 1, 2, 3], { ...next, version: 1 });
await add('expired next root', false, [0, 1, 2, 3], { ...next, expires: now });
await add('expired trusted root', false, [0, 1, 2, 3], next, 'trust-update-root+jws', {
  ...root,
  expires: now,
});
await add('root and release key reuse', false, [0, 1, 2, 3], { ...next, release: role([2]) });
const conflict = { ...next, expires: next.expires + 1 };
cases.push({
  name: 'old and new sign different roots',
  accepted: false,
  root,
  next,
  now,
  envelope: {
    signatures: [
      await sign(next, 0),
      await sign(next, 1),
      await sign(conflict, 2),
      await sign(conflict, 3),
    ],
  },
});
console.log(JSON.stringify({ cases }, null, 2));
