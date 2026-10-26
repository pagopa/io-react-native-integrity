import { X509Certificate } from 'crypto';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
import { AsnConvert, OctetString } from '@peculiar/asn1-schema';
import {
  AttestationApplicationId,
  NonStandardKeyDescription,
  SecurityLevel,
  VerifiedBootState,
  id_ce_keyDescription,
} from '@peculiar/asn1-android';

export { SecurityLevel, VerifiedBootState };

/**
 * Relevant fields of the key attestation extension (KeyDescription).
 * Binary fields are lowercase hex encoded.
 * Hardware enforced values are read only from the teeEnforced (hardwareEnforced) authorization list.
 * {@link https://source.android.com/docs/security/features/keystore/attestation#schema}
 */
export type AttestationRecord = {
  attestationVersion: number;
  attestationSecurityLevel: SecurityLevel;
  keymasterVersion: number;
  keymasterSecurityLevel: SecurityLevel;
  attestationChallenge: Buffer;
  purposes?: number[];
  origin?: number;
  rootOfTrust?: {
    verifiedBootKey: string;
    deviceLocked: boolean;
    verifiedBootState: VerifiedBootState;
    verifiedBootHash?: string;
  };
  osVersion?: number;
  osPatchLevel?: number;
  vendorPatchLevel?: number;
  bootPatchLevel?: number;
  attestationApplicationId?: {
    packages: { name: string; version: number }[];
    signatureDigests: string[];
  };
};

/**
 * The certificate which contains the key attestation extension along with the parsed record.
 */
export type CertificateWithAttestation = {
  certificate: X509Certificate;
  record: AttestationRecord;
};

/**
 * Converts an ASN.1 OCTET STRING to a {@link Buffer}.
 * Some fields (e.g. the ones of AttestationApplicationId) are decoded as raw ArrayBuffer
 * instead of OctetString, regardless of their declared type, so both are handled.
 * @param value - The decoded OCTET STRING.
 * @returns the bytes of the value.
 */
const toBuffer = (value: OctetString | ArrayBuffer) =>
  Buffer.from(value instanceof ArrayBuffer ? value : value.buffer);

const toHex = (value: OctetString | ArrayBuffer) =>
  toBuffer(value).toString('hex');

/**
 * Extracts the raw value of an extension from a certificate.
 * @param certificate - The {@link X509Certificate} to inspect.
 * @param oid - The OID of the extension.
 * @returns the extension value or undefined if the extension is not present.
 */
const extractExtensionValue = (certificate: X509Certificate, oid: string) => {
  const asn1 = asn1js.fromBER(certificate.raw);
  const parsedCertificate = new pkijs.Certificate({ schema: asn1.result });
  return parsedCertificate.extensions
    ?.find((e) => e.extnID === oid)
    ?.extnValue.getValue();
};

/**
 * Tags of the AuthorizationList supported by the parser.
 * {@link https://source.android.com/docs/security/features/keystore/attestation#schema}
 */
const SUPPORTED_AUTHORIZATION_TAGS = new Set([
  1, 2, 3, 5, 6, 10, 200, 203, 303, 305, 400, 401, 402, 405, 503, 504, 505, 506,
  507, 508, 509, 600, 601, 701, 702, 703, 704, 705, 706, 709, 710, 711, 712,
  713, 714, 715, 716, 717, 718, 719, 720, 723, 724,
]);
// Indexes of the softwareEnforced and teeEnforced (hardwareEnforced) authorization lists in the KeyDescription
const AUTHORIZATION_LIST_INDEXES = [6, 7];

/**
 * Removes the authorizations with tags not supported by the parser, which would otherwise make the
 * whole parsing fail on devices with a newer KeyMint version (e.g. new algorithms or tags).
 * Only supported tags are read, so the dropped authorizations are never evaluated.
 * @param extensionValue - The value of the key attestation extension.
 * @returns the re-encoded extension value.
 */
const stripUnsupportedAuthorizations = (extensionValue: ArrayBuffer) => {
  const { result, offset } = asn1js.fromBER(extensionValue);
  if (offset === -1 || !(result instanceof asn1js.Sequence)) {
    throw new Error('Invalid key attestation extension');
  }
  for (const index of AUTHORIZATION_LIST_INDEXES) {
    const list = result.valueBlock.value[index];
    if (!(list instanceof asn1js.Sequence)) {
      throw new Error('Invalid key attestation authorization list');
    }
    list.valueBlock.value = list.valueBlock.value.filter(
      (authorization) =>
        authorization.idBlock.tagClass === 3 && // context-specific
        SUPPORTED_AUTHORIZATION_TAGS.has(authorization.idBlock.tagNumber)
    );
  }
  return result.toBER(false);
};

/**
 * Parses the DER encoded key attestation extension.
 * @param extensionValue - The value of the key attestation extension.
 * @returns the parsed {@link AttestationRecord}.
 */
export const parseAttestationRecord = (
  extensionValue: ArrayBuffer
): AttestationRecord => {
  const keyDescription = AsnConvert.parse(
    stripUnsupportedAuthorizations(extensionValue),
    NonStandardKeyDescription
  );
  const hardwareEnforced = keyDescription.teeEnforced;
  const rootOfTrust = hardwareEnforced.findProperty('rootOfTrust');
  const encodedApplicationId = keyDescription.softwareEnforced.findProperty(
    'attestationApplicationId'
  );
  const applicationId = encodedApplicationId
    ? AsnConvert.parse(encodedApplicationId.buffer, AttestationApplicationId)
    : undefined;

  return {
    attestationVersion: keyDescription.attestationVersion,
    attestationSecurityLevel: keyDescription.attestationSecurityLevel,
    keymasterVersion: keyDescription.keymasterVersion,
    keymasterSecurityLevel: keyDescription.keymasterSecurityLevel,
    attestationChallenge: Buffer.from(
      keyDescription.attestationChallenge.buffer
    ),
    purposes: hardwareEnforced.findProperty('purpose')?.map((p) => p),
    origin: hardwareEnforced.findProperty('origin'),
    rootOfTrust: rootOfTrust && {
      verifiedBootKey: toHex(rootOfTrust.verifiedBootKey),
      deviceLocked: rootOfTrust.deviceLocked,
      verifiedBootState: rootOfTrust.verifiedBootState,
      verifiedBootHash: rootOfTrust.verifiedBootHash
        ? toHex(rootOfTrust.verifiedBootHash)
        : undefined,
    },
    osVersion: hardwareEnforced.findProperty('osVersion'),
    osPatchLevel: hardwareEnforced.findProperty('osPatchLevel'),
    vendorPatchLevel: hardwareEnforced.findProperty('vendorPatchLevel'),
    bootPatchLevel: hardwareEnforced.findProperty('bootPatchLevel'),
    attestationApplicationId: applicationId && {
      packages: applicationId.packageInfos.map((info) => ({
        name: toBuffer(info.packageName).toString('utf-8'),
        version: info.version,
      })),
      // An empty SET OF is decoded as undefined
      signatureDigests: (applicationId.signatureDigests ?? []).map((digest) =>
        toHex(digest)
      ),
    },
  };
};

/**
 * The attestation records of a key attestation chain.
 */
export type AttestationRecords = {
  /** The attested key, i.e. the first certificate of the chain. */
  leaf: CertificateWithAttestation;
  /** The app attest key which signed the leaf certificate, if any. */
  attestKey?: CertificateWithAttestation;
};

/**
 * Finds and parses the key attestation extensions of a chain.
 * Only the leaf certificate and, when the key has been attested by an app attest key (API 31+),
 * the attest key certificate which immediately follows it can contain the extension.
 * Any other position is rejected: this prevents an adversary from appending a certificate with an
 * attestation record of their choice, signed by a key attested by the TEE, to an otherwise trusted chain,
 * as the attest key is also required to have only the ATTEST_KEY purpose, see {@link evaluateAttestKey}.
 * {@link https://developer.android.com/privacy-and-security/security-key-attestation#verifying}
 * @param x509Chain - The chain of {@link X509Certificate} certificates, from the leaf to the root.
 * @returns the {@link AttestationRecords}.
 * @throws {Error} - If no key attestation extension is found or it is in an unexpected position.
 */
export const findAttestationRecords = (
  x509Chain: X509Certificate[]
): AttestationRecords => {
  const records = x509Chain.map((certificate) => {
    const extensionValue = extractExtensionValue(
      certificate,
      id_ce_keyDescription
    );
    return extensionValue
      ? { certificate, record: parseAttestationRecord(extensionValue) }
      : undefined;
  });
  const [leaf, attestKey, ...others] = records;
  if (!leaf) {
    throw new Error('No key attestation extension found in the leaf');
  }
  if (others.some((record) => record !== undefined)) {
    throw new Error('Unexpected key attestation extension in the chain');
  }
  return { leaf, attestKey };
};
