import { google, type playintegrity_v1 } from 'googleapis';
import { X509Certificate } from 'crypto';
import * as fs from 'fs';
import * as crypto from 'crypto';
import {
  findAttestationRecord,
  type AttestationRecord,
} from './keyDescription';
import {
  evaluateAttestationPolicy,
  type AttestationPolicy,
  type VerifiedOs,
} from './attestationPolicy';

/**
 * Simplified type definition for the Certificate Revocation List (CRL) object.
 */
export type CRL = {
  entries: Record<
    string,
    { status: string; expires?: string; reason?: string; comment?: string }
  >;
};

// Certificate Revocation status List
// https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status
const CRL_URL = 'https://android.googleapis.com/attestation/status';
// Public keys of the Google Hardware Attestation Root CAs.
// The RSA key is used by the factory provisioned chains and the legacy remotely provisioned chains,
// while the ECDSA key belongs to the "Key Attestation CA1" root used by the newer remotely provisioned chains.
// https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
const GOOGLE_ROOT_PUBLIC_KEY_FILES = [
  'googleHardwareAttestationRoot.key',
  'googleHardwareAttestationRootEcdsa.key',
];
// Maximum age of a Play Integrity token
const PLAY_INTEGRITY_MAX_AGE_MS = 15 * 60 * 1000;

export const playintegrity = google.playintegrity('v1');

/**
 * Calls the Google Play Integrity API to verify and decrypt an integrity token.
 * @param credentialClientEmail - The service account email.
 * @param credentialPrivateKey - The private key of the service account.
 * @param packageName - The package name of the app which generated the integrity token.
 * @param integrityToken - The integrity token to verify.
 * @returns an object containing the result of the integrity token verification. This token shouldn't be returned to the client.
 * A simple yes/no answer should be returned to the client instead, based on the result of the verification.
 */
export const verifyIntegrityToken = async (
  credentialClientEmail: string,
  credentialPrivateKey: string,
  packageName: string,
  integrityToken: string
) => {
  let jwtClient = new google.auth.JWT(
    credentialClientEmail,
    undefined,
    credentialPrivateKey,
    ['https://www.googleapis.com/auth/playintegrity']
  );
  google.options({ auth: jwtClient });
  return await playintegrity.v1.decodeIntegrityToken({
    packageName,
    requestBody: {
      integrityToken,
    },
  });
};

/**
 * Checks the verdict of a decoded Play Integrity token.
 * {@link https://developer.android.com/google/play/integrity/verdicts}
 * @param payload - The decoded token payload.
 * @param expected.packageName - The package name of the app.
 * @param expected.requestHash - The request hash provided by the app when requesting the token.
 * @param expected.requirePlayRecognized - Whether the app must be recognized by Google Play.
 * @param expected.now - The current time.
 * @throws {Error} - If the verdict doesn't meet the expected values.
 */
export const evaluatePlayIntegrityVerdict = (
  payload: playintegrity_v1.Schema$TokenPayloadExternal,
  expected: {
    packageName: string;
    requestHash: string;
    requirePlayRecognized: boolean;
    now?: Date;
  }
) => {
  const { requestDetails, appIntegrity, deviceIntegrity } = payload;
  if (requestDetails?.requestPackageName !== expected.packageName) {
    throw new Error('Request package name mismatch');
  }
  if (requestDetails.requestHash !== expected.requestHash) {
    throw new Error('Request hash mismatch');
  }
  const timestamp = Number(requestDetails.timestampMillis);
  const now = (expected.now ?? new Date()).getTime();
  if (!timestamp || now - timestamp > PLAY_INTEGRITY_MAX_AGE_MS) {
    throw new Error('Integrity token is too old');
  }
  if (appIntegrity?.packageName !== expected.packageName) {
    throw new Error('App package name mismatch');
  }
  if (
    expected.requirePlayRecognized &&
    appIntegrity.appRecognitionVerdict !== 'PLAY_RECOGNIZED'
  ) {
    throw new Error('App is not recognized by Google Play');
  }
  if (
    !deviceIntegrity?.deviceRecognitionVerdict?.includes(
      'MEETS_DEVICE_INTEGRITY'
    )
  ) {
    throw new Error('Device does not meet integrity');
  }
};

/**
 * Options to verify a key attestation.
 * Besides the {@link AttestationPolicy}, the trusted roots and the revocation list can be overridden.
 */
export type AttestationVerificationOptions = AttestationPolicy & {
  /** Trusted root public keys, the Google Hardware Attestation Root CAs by default. */
  rootPublicKeys?: crypto.KeyObject[];
  /** Loader of the revocation list, the Google attestation status list by default. */
  getCrl?: () => Promise<CRL>;
  /** The current time used to validate the certificates. */
  now?: Date;
};

/**
 * Result of a successful key attestation verification.
 */
export type VerifiedAttestation = {
  /** The {@link VerifiedOs} running on the device. */
  os: VerifiedOs;
  /** The public key of the attested key pair. */
  publicKey: crypto.KeyObject;
  /** The parsed key attestation extension. */
  record: AttestationRecord;
};

/**
 * Verifies a key attestation which is a signed statement from a secure hardware module that attests to the security properties of the module.
 * On Android it is represented as a chain of X.509 certificates.
 * The native implementation contacates the chain of certificates into a single base64 encoded string divided by commas.
 * {@link https://developer.android.com/training/articles/security-key-attestation}
 * 1st and 2nd steps are not implemented here as they are done on the client side.
 * Functions used to verify the attestation have their relative steps commented in the TSdoc.
 * Even though some steps might be joined in a single function, they are separated in the comments for clarity at the cost of some repetition.
 * The 5th step is not implemented as it is only implemented in newer chains.
 * The 7th step compares the attestation extension data with the expected values, see {@link evaluateAttestationPolicy}.
 * Devices running the stock OS or GrapheneOS with a locked bootloader are accepted.
 * @param x509Array - The chain of X.509 certificates in base64 format divided by commas.
 * @param options - The {@link AttestationVerificationOptions}.
 * @returns the {@link VerifiedAttestation}.
 * @throws {Error} - If the attestation is invalid.
 */
export const verifyAttestation = async (
  x509Array: string,
  options: AttestationVerificationOptions
): Promise<VerifiedAttestation> => {
  // We split the chain of certificates and convert them to PEM format to be parsed by the X509Certificate class
  const decodedString = Buffer.from(x509Array, 'base64').toString('utf-8');
  const certificates = decodedString.split(',');
  const x509Chain = certificates.map((cert) => {
    return new X509Certificate(base64ToPem(cert));
  });
  validateIssuance(
    x509Chain,
    options.rootPublicKeys ?? getGoogleRootPublicKeys(),
    options.now ?? new Date()
  );
  validateRevokation(x509Chain, await (options.getCrl ?? fetchGoogleCrl)());
  // 6.
  const { certificate, record } = findAttestationRecord(x509Chain);
  // 7.
  const os = evaluateAttestationPolicy(record, options);
  return { os, publicKey: certificate.publicKey, record };
};

/**
 * A device which has been registered with a verified key attestation.
 */
export type RegisteredDevice = VerifiedAttestation;

/**
 * Options to verify an integrity assertion.
 */
export type AssertionVerificationOptions = Omit<
  AttestationVerificationOptions,
  'challenge'
> & {
  /**
   * Verifies a Play Integrity token for the given request hash, it must throw if the verdict is not valid.
   * When undefined Play Integrity is considered not available.
   */
  verifyPlayIntegrity?: (
    integrityToken: string,
    requestHash: string
  ) => Promise<void>;
};

/**
 * Data sent by the app to assert its integrity.
 */
export type AssertionRequest = {
  /** The client data signed by the hardware key. */
  clientData: string;
  /** The base64 encoded DER ECDSA signature of the client data made with the registered hardware key. */
  signature: string;
  /** The Play Integrity token requested with the SHA-256 hex digest of the client data as request hash. */
  integrityToken?: string;
  /** The fresh key attestation generated with the SHA-256 hex digest of the client data as challenge. */
  attestationAssertion?: string;
};

/**
 * Result of a successful assertion verification.
 */
export type VerifiedAssertion =
  | { method: 'play_integrity' }
  | { method: 'key_attestation'; os: VerifiedOs };

/**
 * Verifies an integrity assertion of a registered device.
 * Both the Play Integrity token and the fresh key attestation are expected to be sent by the app:
 * 1. the client data must be signed by the hardware key registered with {@link verifyAttestation};
 * 2. if the Play Integrity token is valid the assertion is accepted;
 * 3. otherwise, as fallback, the fresh key attestation must satisfy the same policy of the registration,
 *    with the SHA-256 hex digest of the client data as challenge, and must come from the same device state
 *    (verified boot state and verified boot key) of the registration.
 * @param device - The {@link RegisteredDevice}.
 * @param request - The {@link AssertionRequest}.
 * @param options - The {@link AssertionVerificationOptions}.
 * @returns the {@link VerifiedAssertion}.
 * @throws {Error} - If the assertion is invalid.
 */
export const verifyAndroidAssertion = async (
  device: RegisteredDevice,
  request: AssertionRequest,
  options: AssertionVerificationOptions
): Promise<VerifiedAssertion> => {
  const isSignatureValid = crypto
    .createVerify('SHA256')
    .update(request.clientData)
    .verify(device.publicKey, request.signature, 'base64');
  if (!isSignatureValid) {
    throw new Error('Invalid hardware signature');
  }

  const requestHash = crypto
    .createHash('sha256')
    .update(request.clientData)
    .digest('hex');
  const failures: string[] = [];

  if (request.integrityToken && options.verifyPlayIntegrity) {
    try {
      await options.verifyPlayIntegrity(request.integrityToken, requestHash);
      return { method: 'play_integrity' };
    } catch (e) {
      failures.push(`Play Integrity: ${errorMessage(e)}`);
    }
  } else {
    failures.push('Play Integrity: not available');
  }

  if (request.attestationAssertion) {
    try {
      const { os, record } = await verifyAttestation(
        request.attestationAssertion,
        { ...options, challenge: requestHash }
      );
      assertSameDeviceState(device.record, record);
      return { method: 'key_attestation', os };
    } catch (e) {
      failures.push(`Key attestation: ${errorMessage(e)}`);
    }
  } else {
    failures.push('Key attestation: not provided');
  }

  throw new Error(`Integrity assertion failed. ${failures.join('. ')}`);
};

/**
 * Checks that a fresh key attestation comes from the same device state of the registration.
 * @param registered - The attestation record of the registration.
 * @param current - The attestation record of the assertion.
 * @throws {Error} - If the verified boot state or key differ.
 */
const assertSameDeviceState = (
  registered: AttestationRecord,
  current: AttestationRecord
) => {
  if (
    registered.rootOfTrust?.verifiedBootState !==
      current.rootOfTrust?.verifiedBootState ||
    registered.rootOfTrust?.verifiedBootKey !==
      current.rootOfTrust?.verifiedBootKey
  ) {
    throw new Error('Device state differs from the registration');
  }
};

/**
 * 3.
 * Obtain a reference to the X.509 certificate chain parsing and validation library that is most appropriate for your toolset.
 * Verify that the root public certificate is trustworthy and that each certificate signs the next certificate in the chain.
 * @param x509Chain - The chain of {@link X509Certificate} certificates.
 * @param rootPublicKeys - The trusted root public keys.
 * @param now - The current time.
 * @throws {Error} - If the chain is invalid.
 */
const validateIssuance = (
  x509Chain: X509Certificate[],
  rootPublicKeys: crypto.KeyObject[],
  now: Date
) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');

  // Check dates
  const datesValid = x509Chain.every(
    (c) => new Date(c.validFrom) < now && now < new Date(c.validTo)
  );
  if (!datesValid) throw new Error('Certificates expired');

  // Check that each certificate, except for the last, is issued by the subsequent one.
  if (x509Chain.length >= 2) {
    for (let i = 0; i < x509Chain.length - 1; i++) {
      const subject = x509Chain[i];
      const issuer = x509Chain[i + 1];

      if (
        !subject ||
        !issuer ||
        subject.checkIssued(issuer) === false ||
        subject.verify(issuer.publicKey) === false
      ) {
        throw new Error('Certificate chain is invalid');
      }
    }
  }

  // Ensure that the last certificate in the chain is signed by one of the Google Hardware Attestation Root CAs.
  const rootCert = x509Chain[x509Chain.length - 1]; // Last certificate in the chain is the root certificate
  if (!rootCert || !rootPublicKeys.some((pk) => isSignedBy(rootCert, pk))) {
    throw new Error(
      'Root certificate is not signed by Google Hardware Attestation Root CA'
    );
  }
};

/**
 * Fetches the Google attestation status list.
 * @returns the {@link CRL}.
 */
const fetchGoogleCrl = async () => {
  const res = await fetch(CRL_URL, { method: 'GET' });
  if (!res.ok) throw new Error('Failed to fetch CRL');
  return (await res.json()) as CRL; // Add type assertion for crl
};

/**
 * 4.
 * Check each certificate's revocation status to ensure that none of the certificates have been revoked.
 * @param x509Chain - The chain of {@link X509Certificate} certificates.
 * @param crl - The {@link CRL}.
 * @throws {Error} - If any certificate in the chain is revoked.
 */
const validateRevokation = (x509Chain: X509Certificate[], crl: CRL) => {
  if (x509Chain.length === 0) throw new Error('No certificates provided');
  // The CRL entries are indexed by lowercase hex serial numbers without leading zeros,
  // while X509Certificate returns uppercase hex serial numbers.
  const revokedSerials = new Set(
    Object.keys(crl.entries).map(normalizeSerialNumber)
  );
  const isExpired = x509Chain.some((cert) => {
    return revokedSerials.has(normalizeSerialNumber(cert.serialNumber));
  });
  if (isExpired) throw new Error('Certificate is revoked');
};

/**
 * Loads the public keys of the Google Hardware Attestation Root CAs.
 * @returns the list of the root public keys.
 */
export const getGoogleRootPublicKeys = () =>
  GOOGLE_ROOT_PUBLIC_KEY_FILES.map((file) =>
    crypto.createPublicKey(
      fs.readFileSync(require('path').resolve(__dirname, file))
    )
  );

/**
 * Checks whether a certificate is signed by the given public key.
 * @param certificate - The {@link X509Certificate} to check.
 * @param publicKey - The public key of the issuer.
 * @returns true if the signature is valid, false otherwise.
 */
const isSignedBy = (
  certificate: X509Certificate,
  publicKey: crypto.KeyObject
) => {
  try {
    return certificate.verify(publicKey);
  } catch {
    return false;
  }
};

/**
 * Normalizes a hex serial number to lowercase without leading zeros.
 * @param serialNumber - The hex serial number.
 * @returns the normalized serial number.
 */
export const normalizeSerialNumber = (serialNumber: string) =>
  serialNumber.toLowerCase().replace(/^0+(?=.)/, '');

const errorMessage = (e: unknown) => (e instanceof Error ? e.message : `${e}`);

const base64ToPem = (b64cert: string) => {
  return (
    '-----BEGIN CERTIFICATE-----\n' +
    b64cert.trim() +
    '\n-----END CERTIFICATE-----'
  );
};
