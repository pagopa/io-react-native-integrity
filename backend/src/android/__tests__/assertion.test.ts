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
    assertion: Partial<TestAttestationParams> = {}
  ) => {
    const attestation = await createAttestation(root, registration);
    const device: RegisteredDevice = await verifyAttestation(
      attestation.encoded,
      testOptions(root)
    );
    const fresh = await createAttestation(root, {
      ...registration,
      challenge: REQUEST_HASH,
      ...assertion,
    });
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
    const { device, signature, attestationAssertion } = await setup(
      grapheneOsParams(),
      {
        verifiedBootKey: grapheneOsParams().verifiedBootKey.replace(
          /^../,
          'f0'
        ),
      }
    );
    const result = verifyAndroidAssertion(
      device,
      { clientData: CLIENT_DATA, signature, attestationAssertion },
      {
        ...options(),
        trustedSelfSignedBootKeys: new Set([
          device.record.rootOfTrust?.verifiedBootKey ?? '',
          grapheneOsParams().verifiedBootKey.replace(/^../, 'f0'),
        ]),
      }
    );
    await assert.rejects(result, /Device state differs from the registration/);
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
