import { before, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { SecurityLevel, VerifiedBootState } from '@peculiar/asn1-android';
import {
  getGoogleRootPublicKeys,
  normalizeSerialNumber,
  verifyAttestation,
} from '../androidIntegrity';
import {
  createAttestation,
  createTestRoot,
  grapheneOsParams,
  readPemChainFixture,
  stockParams,
  testOptions,
  type TestRoot,
} from './helpers';

describe('verifyAttestation', () => {
  let root: TestRoot;

  before(async () => {
    root = await createTestRoot();
  });

  it('accepts a locked device running the stock OS', async () => {
    const { encoded } = await createAttestation(root, stockParams());
    const result = await verifyAttestation(encoded, testOptions(root));
    assert.equal(result.os, 'stock');
  });

  it('accepts a locked device running GrapheneOS', async () => {
    const { encoded } = await createAttestation(root, grapheneOsParams());
    const result = await verifyAttestation(encoded, testOptions(root));
    assert.equal(result.os, 'grapheneos');
    assert.equal(
      result.record.rootOfTrust?.verifiedBootState,
      VerifiedBootState.selfSigned
    );
  });

  it('matches the GrapheneOS verified boot key case insensitively', async () => {
    const { encoded } = await createAttestation(root, grapheneOsParams());
    const keys = new Set([grapheneOsParams().verifiedBootKey.toLowerCase()]);
    const result = await verifyAttestation(
      encoded,
      testOptions(root, { trustedSelfSignedBootKeys: keys })
    );
    assert.equal(result.os, 'grapheneos');
  });

  it('does not enforce any patch level', async () => {
    const { encoded } = await createAttestation(
      root,
      grapheneOsParams({ osPatchLevel: 201801 })
    );
    const result = await verifyAttestation(encoded, testOptions(root));
    assert.equal(result.os, 'grapheneos');
  });

  const rejections: [string, Parameters<typeof grapheneOsParams>[0], RegExp][] =
    [
      [
        'a self-signed OS with a verified boot key not in the allowlist',
        { verifiedBootKey: '34'.repeat(32) },
        /Verified boot key is not allowed/,
      ],
      [
        'an unlocked bootloader',
        { deviceLocked: false },
        /Bootloader is unlocked/,
      ],
      [
        'an unverified boot state',
        { verifiedBootState: VerifiedBootState.unverified },
        /Verified boot state is not verified or self-signed/,
      ],
      [
        'a failed boot state',
        { verifiedBootState: VerifiedBootState.failed },
        /Verified boot state is not verified or self-signed/,
      ],
      [
        'a software attestation',
        {
          securityLevel: SecurityLevel.software,
          keymasterSecurityLevel: SecurityLevel.software,
        },
        /not hardware backed/,
      ],
      [
        'mismatching security levels',
        { keymasterSecurityLevel: SecurityLevel.trustedEnvironment },
        /security level does not match/,
      ],
      ['a wrong challenge', { challenge: 'other' }, /Challenge mismatch/],
      ['an imported key', { origin: 2 }, /not been generated/],
      [
        'a wrong package name',
        { packageName: 'com.example.other' },
        /Invalid package name/,
      ],
      [
        'a wrong app signing certificate',
        { signatureDigests: ['cd'.repeat(32)] },
        /Invalid app signing certificate/,
      ],
      [
        'a missing verified boot hash',
        { withBootHash: false },
        /Missing verified boot hash/,
      ],
    ];

  for (const [name, params, error] of rejections) {
    it(`rejects ${name}`, async () => {
      const { encoded } = await createAttestation(
        root,
        grapheneOsParams(params)
      );
      await assert.rejects(
        verifyAttestation(encoded, testOptions(root)),
        error
      );
    });
  }

  it('rejects GrapheneOS when the app signing certificate digests are not configured', async () => {
    const { encoded } = await createAttestation(root, grapheneOsParams());
    await assert.rejects(
      verifyAttestation(encoded, testOptions(root, { signatureDigests: [] })),
      /digests are required to accept a self-signed OS/
    );
  });

  it('accepts the stock OS when the app signing certificate digests are not configured', async () => {
    const { encoded } = await createAttestation(
      root,
      stockParams({ signatureDigests: ['cd'.repeat(32)] })
    );
    const result = await verifyAttestation(
      encoded,
      testOptions(root, { signatureDigests: [] })
    );
    assert.equal(result.os, 'stock');
  });

  it('rejects a chain which is not issued by a trusted root', async () => {
    const otherRoot = await createTestRoot();
    const { encoded } = await createAttestation(otherRoot, grapheneOsParams());
    await assert.rejects(
      verifyAttestation(encoded, testOptions(root)),
      /Root certificate is not signed/
    );
  });

  it('rejects a revoked certificate regardless of the serial number format', async () => {
    const { encoded } = await createAttestation(
      root,
      grapheneOsParams(),
      '00ABCDEF01'
    );
    await assert.rejects(
      verifyAttestation(
        encoded,
        testOptions(root, {
          getCrl: async () => ({
            entries: { abcdef01: { status: 'REVOKED' } },
          }),
        })
      ),
      /Certificate is revoked/
    );
  });

  it('normalizes serial numbers', () => {
    assert.equal(normalizeSerialNumber('00ABCDEF01'), 'abcdef01');
    assert.equal(normalizeSerialNumber('0'), '0');
  });

  describe('real Google chains', () => {
    const realOptions = (challenge: string, now: string) => ({
      challenge,
      packageNames: ['com.google.android.attestation'],
      signatureDigests: [
        '103938ee4537e59e8ee792f654504fb8346fc6b346d0bbc4415fc339fcfc8ec1',
      ],
      trustedSelfSignedBootKeys: new Set<string>(),
      rootPublicKeys: getGoogleRootPublicKeys(),
      getCrl: async () => ({ entries: {} }),
      now: new Date(now),
    });

    it('accepts a chain rooted at the Google RSA root', async () => {
      const result = await verifyAttestation(
        readPemChainFixture('google-caiman-tee-ec-rkp.pem'),
        realOptions(
          'd688d763-6118-4ca6-94b2-e6cd9ed7e4e4',
          '2025-10-01T00:00:00Z'
        )
      );
      assert.equal(result.os, 'stock');
    });

    it('accepts a chain rooted at the Google Key Attestation CA1 ECDSA root', async () => {
      const result = await verifyAttestation(
        readPemChainFixture('google-tegu-sb-ec-2026-root.pem'),
        realOptions(
          '90578e1d-f5bf-4ccf-a27f-a4f4d89ee21f',
          '2026-03-01T00:00:00Z'
        )
      );
      assert.equal(result.os, 'stock');
      assert.equal(
        result.record.attestationSecurityLevel,
        SecurityLevel.strongBox
      );
    });
  });
});
