import { before, describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import * as crypto from 'crypto';
import {
  evaluatePlayIntegrityVerdict,
  verifyAndroidAssertion,
  verifyAttestation,
  type AssertionVerificationOptions,
  type RegisteredDevice,
} from '../androidIntegrity';
import {
  NOW,
  PACKAGE_NAME,
  createAttestation,
  createTestRoot,
  grapheneOsParams,
  stockParams,
  testOptions,
  type TestAttestationParams,
  type TestRoot,
} from './helpers';

const CLIENT_DATA = JSON.stringify({ challenge: 'assertion-challenge' });
const REQUEST_HASH = crypto
  .createHash('sha256')
  .update(CLIENT_DATA)
  .digest('hex');

describe('verifyAndroidAssertion', () => {
  let root: TestRoot;

  before(async () => {
    root = await createTestRoot();
  });

  /**
   * Registers a device and prepares a signed assertion request with a fresh key attestation.
   */
  const setup = async (
    registration: TestAttestationParams,
    assertion: Partial<TestAttestationParams> = {},
    // The attest key of the fresh attestation: the registered one by default,
    // a new one to simulate another device or null for none
    freshAttestKey?: 'new' | null,
    registrationAttestKey?: null
  ) => {
    const attestation = await createAttestation(root, registration, {
      attestKey: registrationAttestKey,
    });
    const device: RegisteredDevice = await verifyAttestation(
      attestation.encoded,
      testOptions(root)
    );
    const fresh = await createAttestation(
      root,
      {
        ...registration,
        challenge: REQUEST_HASH,
        ...assertion,
      },
      {
        attestKey:
          freshAttestKey === null
            ? null
            : freshAttestKey === 'new'
              ? undefined
              : attestation.attestKey,
      }
    );
    const signature = crypto
      .createSign('SHA256')
      .update(CLIENT_DATA)
      .sign(attestation.privateKey, 'base64');
    return { device, signature, attestationAssertion: fresh.encoded };
  };

  const options = (
    verifyPlayIntegrity?: AssertionVerificationOptions['verifyPlayIntegrity']
  ): AssertionVerificationOptions => {
    const {
      packageNames,
      signatureDigests,
      trustedSelfSignedBootKeys,
      rootPublicKeys,
      getCrl,
      now,
    } = testOptions(root);
    return {
      packageNames,
      signatureDigests,
      trustedSelfSignedBootKeys,
      rootPublicKeys,
      getCrl,
      now,
      verifyPlayIntegrity,
    };
  };

  it('accepts a valid Play Integrity token', async () => {
    const { device, signature, attestationAssertion } =
      await setup(stockParams());
    let receivedHash: string | undefined;
    const result = await verifyAndroidAssertion(
      device,
      {
        clientData: CLIENT_DATA,
        signature,
        integrityToken: 'token',
        attestationAssertion,
      },
      options(async (_, requestHash) => {
        receivedHash = requestHash;
      })
    );
    assert.deepEqual(result, { method: 'play_integrity' });
    assert.equal(receivedHash, REQUEST_HASH);
  });

  it('falls back on the fresh key attestation when Play Integrity fails', async () => {
    const { device, signature, attestationAssertion } =
      await setup(grapheneOsParams());
    const result = await verifyAndroidAssertion(
      device,
      {
        clientData: CLIENT_DATA,
        signature,
        integrityToken: 'token',
        attestationAssertion,
      },
      options(async () => {
        throw new Error('Device does not meet integrity');
      })
    );
    assert.deepEqual(result, { method: 'key_attestation', os: 'grapheneos' });
  });

  it('falls back on the fresh key attestation when Play Integrity is not available', async () => {
    const { device, signature, attestationAssertion } =
      await setup(grapheneOsParams());
    const result = await verifyAndroidAssertion(
      device,
      { clientData: CLIENT_DATA, signature, attestationAssertion },
      options()
    );
    assert.deepEqual(result, { method: 'key_attestation', os: 'grapheneos' });
  });

  it('rejects an invalid hardware signature', async () => {
    const { device, attestationAssertion } = await setup(grapheneOsParams());
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    const signature = crypto
      .createSign('SHA256')
      .update(CLIENT_DATA)
      .sign(privateKey, 'base64');
    await assert.rejects(
      verifyAndroidAssertion(
        device,
        { clientData: CLIENT_DATA, signature, attestationAssertion },
        options(async () => {})
      ),
      /Invalid hardware signature/
    );
  });

  it('rejects a fresh key attestation with a challenge other than the client data hash', async () => {
    const { device, signature, attestationAssertion } = await setup(
      grapheneOsParams(),
      { challenge: 'stale' }
    );
    await assert.rejects(
      verifyAndroidAssertion(
        device,
        { clientData: CLIENT_DATA, signature, attestationAssertion },
        options()
      ),
      /Key attestation: Challenge mismatch/
    );
  });

  it('rejects a fresh key attestation from a different device state', async () => {
    // The attest key binds the fresh attestation to the registered root of trust, so the
    // registered device state is altered to check this further defense
    const { device, signature, attestationAssertion } =
      await setup(stockParams());
    const registered: RegisteredDevice = {
      ...device,
      record: {
        ...device.record,
        rootOfTrust: device.record.rootOfTrust && {
          ...device.record.rootOfTrust,
          verifiedBootKey: '34'.repeat(32),
        },
      },
    };
    await assert.rejects(
      verifyAndroidAssertion(
        registered,
        { clientData: CLIENT_DATA, signature, attestationAssertion },
        options()
      ),
      /Device state differs from the registration/
    );
  });

  it('rejects a fresh key attestation with a different root of trust than the attest key', async () => {
    const otherKey = grapheneOsParams().verifiedBootKey.replace(/^../, 'f0');
    const { device, signature, attestationAssertion } = await setup(
      grapheneOsParams(),
      { verifiedBootKey: otherKey }
    );
    await assert.rejects(
      verifyAndroidAssertion(
        device,
        { clientData: CLIENT_DATA, signature, attestationAssertion },
        {
          ...options(),
          trustedSelfSignedBootKeys: new Set([
            device.record.rootOfTrust?.verifiedBootKey ?? '',
            otherKey,
          ]),
        }
      ),
      /Attest key root of trust does not match/
    );
  });

  it('rejects when both proofs fail', async () => {
    const { device, signature, attestationAssertion } = await setup(
      grapheneOsParams(),
      { deviceLocked: false }
    );
    await assert.rejects(
      verifyAndroidAssertion(
        device,
        {
          clientData: CLIENT_DATA,
          signature,
          integrityToken: 'token',
          attestationAssertion,
        },
        options(async () => {
          throw new Error('Device does not meet integrity');
        })
      ),
      /Play Integrity: Device does not meet integrity\. Key attestation: Bootloader is unlocked/
    );
  });

  it('rejects when no proof is provided', async () => {
    const { device, signature } = await setup(grapheneOsParams());
    await assert.rejects(
      verifyAndroidAssertion(
        device,
        { clientData: CLIENT_DATA, signature },
        options()
      ),
      /Play Integrity: not available\. Key attestation: not provided/
    );
  });

  describe('attest key pinning', () => {
    it('pins the attest key at registration', async () => {
      const { device } = await setup(grapheneOsParams());
      assert.ok(device.attestKeyPublicKey);
    });

    it('rejects a fresh key attestation relayed from another device running GrapheneOS', async () => {
      // Same OS, model and verified boot key, but a different attest key
      const { device, signature, attestationAssertion } = await setup(
        grapheneOsParams(),
        {},
        'new'
      );
      await assert.rejects(
        verifyAndroidAssertion(
          device,
          { clientData: CLIENT_DATA, signature, attestationAssertion },
          options()
        ),
        /not been signed by the registered attest key/
      );
    });

    it('rejects a fresh key attestation without the registered attest key', async () => {
      const { device, signature, attestationAssertion } = await setup(
        grapheneOsParams(),
        {},
        null
      );
      await assert.rejects(
        verifyAndroidAssertion(
          device,
          { clientData: CLIENT_DATA, signature, attestationAssertion },
          options()
        ),
        /not been signed by the registered attest key/
      );
    });

    it('accepts a fresh key attestation of the stock OS signed by the registered attest key', async () => {
      const { device, signature, attestationAssertion } =
        await setup(stockParams());
      assert.ok(device.attestKeyPublicKey);
      const result = await verifyAndroidAssertion(
        device,
        { clientData: CLIENT_DATA, signature, attestationAssertion },
        options()
      );
      assert.deepEqual(result, { method: 'key_attestation', os: 'stock' });
    });

    it('requires Play Integrity for the stock OS registered without attest key', async () => {
      const { device, signature, attestationAssertion } = await setup(
        stockParams(),
        {},
        null,
        null
      );
      assert.equal(device.attestKeyPublicKey, undefined);
      await assert.rejects(
        verifyAndroidAssertion(
          device,
          { clientData: CLIENT_DATA, signature, attestationAssertion },
          options()
        ),
        /No attest key registered with the device, Play Integrity is required/
      );
    });

    it('requires the app signing certificate digests to accept a fresh key attestation', async () => {
      const { device, signature, attestationAssertion } =
        await setup(stockParams());
      await assert.rejects(
        verifyAndroidAssertion(
          device,
          { clientData: CLIENT_DATA, signature, attestationAssertion },
          { ...options(), signatureDigests: [] }
        ),
        /App signing certificate digests are required/
      );
    });
  });
});

describe('evaluatePlayIntegrityVerdict', () => {
  const payload = (overrides: Record<string, unknown> = {}) => ({
    requestDetails: {
      requestPackageName: PACKAGE_NAME,
      requestHash: REQUEST_HASH,
      timestampMillis: `${NOW.getTime() - 1000}`,
    },
    appIntegrity: {
      packageName: PACKAGE_NAME,
      appRecognitionVerdict: 'UNRECOGNIZED_VERSION',
    },
    deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'] },
    ...overrides,
  });
  const expected = {
    packageName: PACKAGE_NAME,
    requestHash: REQUEST_HASH,
    requirePlayRecognized: false,
    now: NOW,
  };

  it('accepts a valid verdict', () => {
    assert.doesNotThrow(() =>
      evaluatePlayIntegrityVerdict(payload(), expected)
    );
  });

  it('rejects a device which does not meet integrity', () => {
    assert.throws(
      () =>
        evaluatePlayIntegrityVerdict(
          payload({
            deviceIntegrity: {
              deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'],
            },
          }),
          expected
        ),
      /Device does not meet integrity/
    );
  });

  it('rejects a wrong request hash', () => {
    assert.throws(
      () =>
        evaluatePlayIntegrityVerdict(payload(), {
          ...expected,
          requestHash: 'other',
        }),
      /Request hash mismatch/
    );
  });

  it('rejects an old token', () => {
    assert.throws(
      () =>
        evaluatePlayIntegrityVerdict(payload(), {
          ...expected,
          now: new Date(NOW.getTime() + 60 * 60 * 1000),
        }),
      /too old/
    );
  });

  it('rejects an app not recognized by Google Play when required', () => {
    assert.throws(
      () =>
        evaluatePlayIntegrityVerdict(payload(), {
          ...expected,
          requirePlayRecognized: true,
        }),
      /not recognized by Google Play/
    );
  });
});
