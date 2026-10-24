import 'reflect-metadata';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as x509 from '@peculiar/x509';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AttestationApplicationId,
  AttestationPackageInfo,
  AuthorizationList,
  IntegerSet,
  KeyDescription,
  RootOfTrust,
  SecurityLevel,
  VerifiedBootState,
  id_ce_keyDescription,
} from '@peculiar/asn1-android';
import { GRAPHENEOS_ALLOWLIST_SNAPSHOT } from '../grapheneosAllowlist';
import type { AttestationVerificationOptions } from '../androidIntegrity';

x509.cryptoProvider.set(
  crypto.webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]
);

export const FIXTURES_DIR = path.join(__dirname, 'fixtures');
export const PACKAGE_NAME = 'com.ioreactnativeintegrityexample';
export const SIGNATURE_DIGEST = 'ab'.repeat(32);
export const GRAPHENEOS_BOOT_KEY = GRAPHENEOS_ALLOWLIST_SNAPSHOT
  .verifiedBootKeys[0] as string;
export const STOCK_BOOT_KEY = '12'.repeat(32);
export const NOW = new Date('2026-10-23T12:00:00Z');

const EC_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };

/**
 * Values of the synthetic key attestation, defaulting to a device running GrapheneOS.
 */
export type TestAttestationParams = {
  challenge: string | Buffer;
  attestationVersion: number;
  securityLevel: SecurityLevel;
  keymasterSecurityLevel: SecurityLevel;
  verifiedBootState: VerifiedBootState;
  verifiedBootKey: string;
  deviceLocked: boolean;
  withBootHash: boolean;
  packageName: string;
  signatureDigests: string[];
  osPatchLevel: number;
  origin: number;
};

export const grapheneOsParams = (
  overrides: Partial<TestAttestationParams> = {}
): TestAttestationParams => ({
  challenge: 'challenge',
  attestationVersion: 300,
  securityLevel: SecurityLevel.strongBox,
  keymasterSecurityLevel: SecurityLevel.strongBox,
  verifiedBootState: VerifiedBootState.selfSigned,
  verifiedBootKey: GRAPHENEOS_BOOT_KEY,
  deviceLocked: true,
  withBootHash: true,
  packageName: PACKAGE_NAME,
  signatureDigests: [SIGNATURE_DIGEST],
  osPatchLevel: 202610,
  origin: 0,
  ...overrides,
});

export const stockParams = (
  overrides: Partial<TestAttestationParams> = {}
): TestAttestationParams =>
  grapheneOsParams({
    securityLevel: SecurityLevel.trustedEnvironment,
    keymasterSecurityLevel: SecurityLevel.trustedEnvironment,
    verifiedBootState: VerifiedBootState.verified,
    verifiedBootKey: STOCK_BOOT_KEY,
    ...overrides,
  });

const octetString = (value: Buffer | string) =>
  new OctetString(Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf-8'));

/**
 * Encodes a KeyDescription extension with the given values.
 * @param params - The {@link TestAttestationParams}.
 * @returns the DER encoded KeyDescription.
 */
export const encodeKeyDescription = (params: TestAttestationParams) => {
  const applicationId = new AttestationApplicationId({
    packageInfos: [
      new AttestationPackageInfo({
        packageName: octetString(params.packageName),
        version: 1,
      }),
    ],
    signatureDigests: params.signatureDigests.map((d) =>
      octetString(Buffer.from(d, 'hex'))
    ),
  });
  const keyDescription = new KeyDescription({
    attestationVersion: params.attestationVersion,
    attestationSecurityLevel: params.securityLevel,
    keymasterVersion: params.attestationVersion,
    keymasterSecurityLevel: params.keymasterSecurityLevel,
    attestationChallenge: octetString(params.challenge),
    uniqueId: octetString(''),
    softwareEnforced: new AuthorizationList({
      creationDateTime: NOW.getTime(),
      attestationApplicationId: octetString(
        Buffer.from(AsnConvert.serialize(applicationId))
      ),
    }),
    teeEnforced: new AuthorizationList({
      purpose: new IntegerSet([2]),
      algorithm: 3,
      keySize: 256,
      digest: new IntegerSet([4]),
      ecCurve: 1,
      noAuthRequired: null,
      origin: params.origin,
      rootOfTrust: new RootOfTrust({
        verifiedBootKey: octetString(
          Buffer.from(params.verifiedBootKey, 'hex')
        ),
        deviceLocked: params.deviceLocked,
        verifiedBootState: params.verifiedBootState,
        verifiedBootHash: params.withBootHash
          ? octetString(Buffer.alloc(32, 7))
          : undefined,
      }),
      osVersion: 160000,
      osPatchLevel: params.osPatchLevel,
      vendorPatchLevel: params.osPatchLevel * 100 + 5,
      bootPatchLevel: params.osPatchLevel * 100 + 5,
    }),
  });
  return AsnConvert.serialize(keyDescription);
};

/**
 * Encodes a certificate chain like the native module does: the base64 encoding of the
 * comma separated base64 encoded certificates.
 * @param certificates - The DER encoded certificates, from the leaf to the root.
 * @returns the encoded chain.
 */
export const encodeChain = (certificates: (ArrayBuffer | Buffer)[]) =>
  Buffer.from(
    certificates.map((c) => `${Buffer.from(c).toString('base64')}\n`).join(',')
  ).toString('base64');

/**
 * A test root CA which can issue synthetic key attestation chains.
 */
export type TestRoot = {
  keys: crypto.webcrypto.CryptoKeyPair;
  certificate: x509.X509Certificate;
  publicKey: crypto.KeyObject;
};

export const createTestRoot = async (): Promise<TestRoot> => {
  const keys = (await crypto.webcrypto.subtle.generateKey(EC_ALGORITHM, true, [
    'sign',
    'verify',
  ])) as crypto.webcrypto.CryptoKeyPair;
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Test Attestation Root',
    notBefore: new Date('2020-01-01T00:00:00Z'),
    notAfter: new Date('2040-01-01T00:00:00Z'),
    keys,
    signingAlgorithm: EC_ALGORITHM,
    extensions: [new x509.BasicConstraintsExtension(true, undefined, true)],
  });
  return {
    keys,
    certificate,
    publicKey: crypto.createPublicKey({
      key: Buffer.from(certificate.publicKey.rawData),
      format: 'der',
      type: 'spki',
    }),
  };
};

/**
 * A synthetic key attestation chain.
 */
export type TestAttestation = {
  /** The encoded chain, as returned by the native module. */
  encoded: string;
  /** The private key of the attested key, to sign the client data. */
  privateKey: crypto.KeyObject;
  /** The hex serial number of the leaf certificate. */
  leafSerialNumber: string;
};

/**
 * Creates a key attestation chain issued by the test root.
 * @param root - The {@link TestRoot}.
 * @param params - The {@link TestAttestationParams}.
 * @param leafSerialNumber - The hex serial number of the leaf certificate.
 * @returns the {@link TestAttestation}.
 */
export const createAttestation = async (
  root: TestRoot,
  params: TestAttestationParams,
  leafSerialNumber = '00ABCDEF01'
): Promise<TestAttestation> => {
  const keys = (await crypto.webcrypto.subtle.generateKey(EC_ALGORITHM, true, [
    'sign',
    'verify',
  ])) as crypto.webcrypto.CryptoKeyPair;
  const leaf = await x509.X509CertificateGenerator.create({
    serialNumber: leafSerialNumber,
    subject: 'CN=Android Keystore Key',
    issuer: root.certificate.subject,
    notBefore: new Date('1970-01-01T00:00:00Z'),
    notAfter: new Date('2048-01-01T00:00:00Z'),
    publicKey: keys.publicKey,
    signingKey: root.keys.privateKey,
    signingAlgorithm: EC_ALGORITHM,
    extensions: [
      new x509.Extension(
        id_ce_keyDescription,
        false,
        encodeKeyDescription(params)
      ),
    ],
  });
  return {
    encoded: encodeChain([leaf.rawData, root.certificate.rawData]),
    privateKey: crypto.KeyObject.from(keys.privateKey),
    leafSerialNumber,
  };
};

/**
 * Default verification options trusting only the test root and without revoked certificates.
 */
export const testOptions = (
  root: TestRoot,
  overrides: Partial<AttestationVerificationOptions> = {}
): AttestationVerificationOptions => ({
  challenge: 'challenge',
  packageNames: [PACKAGE_NAME],
  signatureDigests: [SIGNATURE_DIGEST],
  trustedSelfSignedBootKeys: new Set(
    GRAPHENEOS_ALLOWLIST_SNAPSHOT.verifiedBootKeys
  ),
  rootPublicKeys: [root.publicKey],
  getCrl: async () => ({ entries: {} }),
  now: NOW,
  ...overrides,
});

/**
 * Reads a PEM fixture with a real chain and encodes it like the native module does.
 * @param name - The name of the fixture.
 * @returns the encoded chain.
 */
export const readPemChainFixture = (name: string) => {
  const pem = fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf-8');
  const certificates =
    pem.match(
      /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
    ) ?? [];
  return encodeChain(
    certificates.map((c) => new crypto.X509Certificate(c).raw)
  );
};

export const readFixture = (name: string) =>
  fs.readFileSync(path.join(FIXTURES_DIR, name), 'utf-8');
