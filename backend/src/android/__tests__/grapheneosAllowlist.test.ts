import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  GRAPHENEOS_ALLOWED_SIGNERS,
  GRAPHENEOS_ALLOWLIST_SNAPSHOT,
  GrapheneOsAllowlist,
} from '../grapheneosAllowlist';
import { parseAllowedSigners, verifySshSignature } from '../sshsig';
import { readFixture } from './helpers';

// The fixtures are signed with a test only key by `ssh-keygen -Y sign -n "attestation keys"`
const ALLOWED_SIGNERS = readFixture('allowed_signers');
const ATTESTATION_JSON = readFixture('attestation.json');
const ATTESTATION_SIG = readFixture('attestation.json.sig');
const OLD_ATTESTATION_JSON = readFixture('attestation-old.json');
const OLD_ATTESTATION_SIG = readFixture('attestation-old.json.sig');
const WRONG_NAMESPACE_SIG = readFixture('attestation-wrong-namespace.json.sig');

describe('verifySshSignature', () => {
  const params = {
    message: Buffer.from(ATTESTATION_JSON),
    armoredSignature: ATTESTATION_SIG,
    allowedSigners: ALLOWED_SIGNERS,
    principal: 'contact@grapheneos.org',
    namespace: 'attestation keys',
  };

  it('verifies a signature made by ssh-keygen', () => {
    assert.doesNotThrow(() => verifySshSignature(params));
  });

  it('rejects a tampered message', () => {
    assert.throws(
      () =>
        verifySshSignature({
          ...params,
          message: Buffer.from(
            ATTESTATION_JSON.replace('1761177600', '1761177601')
          ),
        }),
      /Invalid SSH signature/
    );
  });

  it('rejects a signature with another namespace', () => {
    assert.throws(
      () =>
        verifySshSignature({
          ...params,
          armoredSignature: WRONG_NAMESPACE_SIG,
        }),
      /Unexpected SSH signature namespace/
    );
  });

  it('rejects a signature of another principal', () => {
    assert.throws(
      () => verifySshSignature({ ...params, principal: 'other@example.com' }),
      /not been made by an allowed signer/
    );
  });

  it('rejects a signature made by a key which is not allowed', () => {
    const otherSigners = ALLOWED_SIGNERS.replace(
      /ssh-ed25519 (\S+)/,
      'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
    );
    assert.throws(
      () => verifySshSignature({ ...params, allowedSigners: otherSigners }),
      /not been made by an allowed signer/
    );
  });

  it('honours the namespaces option of allowed_signers', () => {
    const [principals, ...key] = ALLOWED_SIGNERS.trim().split(' ');
    const restricted = `${principals} namespaces="file,git" ${key.join(' ')}`;
    assert.throws(
      () => verifySshSignature({ ...params, allowedSigners: restricted }),
      /not been made by an allowed signer/
    );
    const allowed = `${principals} namespaces="attestation keys" ${key.join(' ')}`;
    assert.doesNotThrow(() =>
      verifySshSignature({ ...params, allowedSigners: allowed })
    );
  });

  it('rejects unsupported allowed_signers options', () => {
    const [principals, ...key] = ALLOWED_SIGNERS.trim().split(' ');
    assert.throws(
      () =>
        parseAllowedSigners(
          `${principals} valid-before="20200101" ${key.join(' ')}`
        ),
      /Unsupported allowed_signers options/
    );
  });
});

describe('GrapheneOsAllowlist', () => {
  it('uses the bundled snapshot until a signed list is applied', () => {
    const allowlist = new GrapheneOsAllowlist();
    assert.equal(allowlist.getTimestamp(), 0);
    assert.deepEqual(
      [...allowlist.getKeys()],
      GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys
    );
  });

  it('applies a signed list and normalizes the keys', () => {
    const allowlist = new GrapheneOsAllowlist({
      allowedSigners: ALLOWED_SIGNERS,
    });
    allowlist.apply(ATTESTATION_JSON, ATTESTATION_SIG);
    assert.equal(allowlist.getTimestamp(), 1761177600);
    assert.deepEqual(
      [...allowlist.getKeys()],
      JSON.parse(ATTESTATION_JSON).verifiedBootKeys.map((k: string) =>
        k.toLowerCase()
      )
    );
  });

  it('rejects a downgrade to an older signed list', () => {
    const allowlist = new GrapheneOsAllowlist({
      allowedSigners: ALLOWED_SIGNERS,
    });
    allowlist.apply(ATTESTATION_JSON, ATTESTATION_SIG);
    assert.throws(
      () => allowlist.apply(OLD_ATTESTATION_JSON, OLD_ATTESTATION_SIG),
      /downgrade detected/
    );
    assert.equal(allowlist.getTimestamp(), 1761177600);
  });

  it('rejects an invalid signature and keeps the current list', () => {
    const allowlist = new GrapheneOsAllowlist({
      allowedSigners: ALLOWED_SIGNERS,
    });
    assert.throws(
      () => allowlist.apply(OLD_ATTESTATION_JSON, ATTESTATION_SIG),
      /Invalid SSH signature/
    );
    assert.equal(allowlist.getTimestamp(), 0);
  });

  it('verifies the real list signed by GrapheneOS with the pinned key', () => {
    const allowlist = new GrapheneOsAllowlist();
    allowlist.apply(
      readFixture('grapheneos-attestation.json'),
      readFixture('grapheneos-attestation.json.sig')
    );
    assert.equal(allowlist.getTimestamp(), 1776709772);
    assert.deepEqual(
      [...allowlist.getKeys()].sort(),
      [...GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys].sort()
    );
  });

  it('pins the GrapheneOS allowed_signers published by GrapheneOS', () => {
    assert.equal(
      GRAPHENEOS_ALLOWED_SIGNERS,
      readFixture('grapheneos-allowed_signers').trim()
    );
  });

  it('rejects a list which is not signed by the pinned GrapheneOS key', () => {
    const allowlist = new GrapheneOsAllowlist();
    assert.throws(
      () => allowlist.apply(ATTESTATION_JSON, ATTESTATION_SIG),
      /not been made by an allowed signer/
    );
    assert.equal(allowlist.getTimestamp(), 0);
  });

  it('refreshes from the network and persists the verified list', async () => {
    const cacheFile = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), 'allowlist-')),
      'cache.json'
    );
    const responses: Record<string, string> = {
      'https://test/attestation.json': ATTESTATION_JSON,
      'https://test/attestation.json.sig': ATTESTATION_SIG,
    };
    const fetchFn = (async (url: string) =>
      new Response(responses[url] ?? '', {
        status: responses[url] ? 200 : 404,
      })) as typeof fetch;
    const options = {
      allowedSigners: ALLOWED_SIGNERS,
      cacheFile,
      attestationUrl: 'https://test/attestation.json',
      signatureUrl: 'https://test/attestation.json.sig',
      fetchFn,
    };
    const allowlist = new GrapheneOsAllowlist(options);
    await allowlist.refresh();
    assert.equal(allowlist.getTimestamp(), 1761177600);

    // A new instance loads the verified list from the cache
    const restored = new GrapheneOsAllowlist(options);
    assert.equal(restored.getTimestamp(), 1761177600);
  });

  it('keeps the current list when the refresh fails', async () => {
    const allowlist = new GrapheneOsAllowlist({
      allowedSigners: ALLOWED_SIGNERS,
      fetchFn: (async () => new Response('', { status: 503 })) as typeof fetch,
    });
    await assert.rejects(allowlist.refresh(), /503/);
    assert.equal(allowlist.getTimestamp(), 0);
    assert.equal(
      allowlist.getKeys().size,
      GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys.length
    );
  });
});
