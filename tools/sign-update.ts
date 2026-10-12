// Explicit development release signer. Production must supply a KMS/HSM KeyCustody in its release pipeline.
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { signJws, SoftwareKeyCustody, jwkThumbprint, normalizePublicJwk } from '@trust/crypto';
import { SecureUpdateClient, type UpdateManifest, type UpdateRoot } from '@trust/sdk-core';

async function main() {
  const [flag, rootFile, manifestFile, outFile, ...extra] = process.argv.slice(2);
  if (
    flag !== '--development-software-key' ||
    !rootFile ||
    !manifestFile ||
    !outFile ||
    extra.length ||
    process.env.NODE_ENV === 'production'
  )
    throw new Error(
      'usage: node tools/sign-update.ts --development-software-key root.json manifest.json output.json (development only)',
    );
  const pem = process.env.UPDATE_SIGNING_KEY_PEM;
  if (!pem) throw new Error('UPDATE_SIGNING_KEY_PEM must be supplied securely');
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('update signer must be Ed25519');
  const publicJwk = normalizePublicJwk(createPublicKey(privateKey).export({ format: 'jwk' }));
  const root = JSON.parse(await readFile(rootFile, 'utf8')) as UpdateRoot,
    manifest = JSON.parse(await readFile(manifestFile, 'utf8')) as UpdateManifest;
  const key = root.release.keys.find((k) => jwkThumbprint(k.jwk) === jwkThumbprint(publicJwk));
  if (!key) throw new Error('update key is not in the release role');
  const custody = new SoftwareKeyCustody();
  custody.add(key.kid, privateKey);
  const envelope = {
    signatures: [
      await signJws({ ...manifest }, { kid: key.kid, typ: 'trust-update-manifest+jws' }, custody),
    ],
  };
  const verifier = new SecureUpdateClient({
    root,
    product: manifest.product,
    platform: manifest.platform,
    channel: manifest.channel,
    store: { get: async () => undefined, set: async () => {}, delete: async () => {} },
  });
  await verifier.verifyManifest(envelope);
  // Never overwrite a published file. Only signed public metadata is emitted.
  await writeFile(outFile, JSON.stringify(envelope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  console.log('Verified development update metadata written.');
}
main().catch(() => {
  console.error(
    'Update signing failed; check development-only arguments, root policy and securely supplied key.',
  );
  process.exitCode = 1;
});
