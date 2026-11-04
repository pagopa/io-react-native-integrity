import { before, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { SecurityLevel, VerifiedBootState } from '@peculiar/asn1-android';
import {
  getGoogleRootPublicKeys,
  normalizeSerialNumber,
  verifyAttestation,
} from '../androidIntegrity';
import {
  createAttestKey,
  createAttestation,
  createTestRoot,
  grapheneOsParams,
  readDerChainFixture,
  readPemChainFixture,
  stockParams,
  testOptions,
  type TestRoot,
} from './helpers';
import { GRAPHENEOS_ALLOWLIST_SNAPSHOT } from '../grapheneosAllowlist';

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
    const { encoded } = await createAttestation(root, grapheneOsParams(), {
      leafSerialNumber: '00ABCDEF01',
    });
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

  describe('app attest key', () => {
    it('returns the attest key public key to be pinned', async () => {
      const { encoded, attestKey } = await createAttestation(
        root,
        grapheneOsParams()
      );
      const result = await verifyAttestation(encoded, testOptions(root));
      assert.ok(attestKey);
      assert.ok(result.attestKeyPublicKey);
      assert.deepEqual(
        result.attestKeyPublicKey.export({ format: 'der', type: 'spki' }),
        Buffer.from(attestKey.certificate.publicKey.rawData)
      );
    });

    it('rejects GrapheneOS without an attest key', async () => {
      const { encoded } = await createAttestation(root, grapheneOsParams(), {
        attestKey: null,
      });
      await assert.rejects(
        verifyAttestation(encoded, testOptions(root)),
        /An attest key is required/
      );
    });

    it('accepts GrapheneOS without an attest key when not required', async () => {
      const { encoded } = await createAttestation(root, grapheneOsParams(), {
        attestKey: null,
      });
      const result = await verifyAttestation(
        encoded,
        testOptions(root, { requireAttestKeyForSelfSigned: false })
      );
      assert.equal(result.os, 'grapheneos');
      assert.equal(result.attestKeyPublicKey, undefined);
    });

    const attestKeyRejections: [
      string,
      Parameters<typeof grapheneOsParams>[0],
      RegExp,
    ][] = [
      [
        'a signing key appended as attest key',
        { purposes: [2] },
        /Attest key has invalid purposes/,
      ],
      [
        'an attest key with another root of trust',
        { verifiedBootKey: '56'.repeat(32) },
        /Attest key root of trust does not match/,
      ],
      [
        'an attest key with another security level',
        {
          securityLevel: SecurityLevel.trustedEnvironment,
          keymasterSecurityLevel: SecurityLevel.trustedEnvironment,
        },
        /Attest key security level does not match/,
      ],
      [
        'an attest key of another app',
        { packageName: 'com.example.other' },
        /Attest key application does not match/,
      ],
      [
        'an attest key with another challenge',
        { challenge: 'other' },
        /Attest key challenge mismatch/,
      ],
    ];

    for (const [name, attestKeyParams, error] of attestKeyRejections) {
      it(`rejects ${name}`, async () => {
        const { encoded } = await createAttestation(root, grapheneOsParams(), {
          attestKeyParams,
        });
        await assert.rejects(
          verifyAttestation(encoded, testOptions(root)),
          error
        );
      });
    }

    it('rejects a key attestation extension beyond the attest key', async () => {
      const attestKey = await createAttestKey(
        root,
        grapheneOsParams({ purposes: [7] })
      );
      const { encoded } = await createAttestation(root, grapheneOsParams(), {
        attestKey,
      });
      // Insert an extra certificate with the extension between the attest key and the root
      const certificates = Buffer.from(encoded, 'base64')
        .toString('utf-8')
        .split(',');
      const extra = certificates[1] as string;
      const tampered = Buffer.from(
        [certificates[0], extra, extra, certificates[2]].join(',')
      ).toString('base64');
      await assert.rejects(
        verifyAttestation(tampered, testOptions(root)),
        /Unexpected key attestation extension|Certificate chain is invalid/
      );
    });
  });

  describe('real GrapheneOS chain (Auditor app on a Pixel 9)', () => {
    const CERTIFICATES = [0, 1, 2, 3, 4].map(
      (i) => `grapheneos-pixel9-auditor/0_cert_${i}.der`
    );
    const ROOT = 'grapheneos-pixel9-auditor/1_google_root_3.der';
    const options = (overrides: Record<string, unknown> = {}) => ({
      challenge: Buffer.from(
        '7387551f024289bff8c37c8f3f5fe676b2949fcec23d391dc00ef40a02f64ea2',
        'hex'
      ),
      packageNames: ['app.attestation.auditor'],
      signatureDigests: [
        '990E04F0864B19F14F84E0E432F7A393F297AB105A22C1E1B10B442A4A62C42C',
      ],
      trustedSelfSignedBootKeys: new Set(
        GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys
      ),
      rootPublicKeys: getGoogleRootPublicKeys(),
      getCrl: async () => ({ entries: {} }),
      now: new Date('2025-11-10T00:00:00Z'),
      ...overrides,
    });

    it('accepts the chain with the Google root and pins the attest key', async () => {
      const result = await verifyAttestation(
        readDerChainFixture([...CERTIFICATES, ROOT]),
        options()
      );
      assert.equal(result.os, 'grapheneos');
      assert.equal(
        result.record.rootOfTrust?.verifiedBootKey,
        '9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de'
      );
      assert.equal(
        result.record.attestationSecurityLevel,
        SecurityLevel.strongBox
      );
      assert.ok(result.attestKeyPublicKey);
    });

    it('accepts the chain without the Google root, as stored by the Auditor app', async () => {
      const result = await verifyAttestation(
        readDerChainFixture(CERTIFICATES),
        options()
      );
      assert.equal(result.os, 'grapheneos');
    });

    it('accepts the chain pinned to its own attest key', async () => {
      const chain = readDerChainFixture([...CERTIFICATES, ROOT]);
      const { attestKeyPublicKey } = await verifyAttestation(chain, options());
      const result = await verifyAttestation(
        chain,
        options({ pinnedAttestKey: attestKeyPublicKey })
      );
      assert.equal(result.os, 'grapheneos');
    });

    const realChainRejections: [string, Record<string, unknown>, RegExp][] = [
      [
        'a verified boot key not in the allowlist',
        { trustedSelfSignedBootKeys: new Set<string>() },
        /Verified boot key is not allowed/,
      ],
      [
        'another app signing certificate',
        { signatureDigests: ['00'.repeat(32)] },
        /Invalid app signing certificate/,
      ],
      ['another challenge', { challenge: 'other' }, /Challenge mismatch/],
      [
        'expired intermediate certificates',
        { now: new Date('2026-10-24T00:00:00Z') },
        /Certificates expired/,
      ],
    ];

    for (const [name, overrides, error] of realChainRejections) {
      it(`rejects ${name}`, async () => {
        await assert.rejects(
          verifyAttestation(
            readDerChainFixture([...CERTIFICATES, ROOT]),
            options(overrides)
          ),
          error
        );
      });
    }

    it('rejects the chain pinned to another attest key', async () => {
      const chain = readDerChainFixture([...CERTIFICATES, ROOT]);
      const { publicKey } = await verifyAttestation(chain, options());
      await assert.rejects(
        verifyAttestation(chain, options({ pinnedAttestKey: publicKey })),
        /not been signed by the registered attest key/
      );
    });
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
