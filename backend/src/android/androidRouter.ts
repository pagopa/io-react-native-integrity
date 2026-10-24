import express, { Router } from 'express';
import { v4 as uuid } from 'uuid';
import {
  evaluatePlayIntegrityVerdict,
  verifyAndroidAssertion,
  verifyAttestation,
  verifyIntegrityToken,
  type AssertionVerificationOptions,
  type RegisteredDevice,
} from './androidIntegrity';
import { GrapheneOsAllowlist } from './grapheneosAllowlist';
import { ANDROID_BUNDLE_IDENTIFIER, GOOGLE_APPLICATION_CREDENTIALS } from '..';

const router: Router = express.Router();

// Validity of the challenges issued by the server
const NONCE_VALIDITY_MS = 5 * 60 * 1000;

// Please note that this is a simple example: issued challenges and registered devices are kept in memory
// and lost every time the server restarts. A real backend must store them in a persistent storage.
const nonces = new Map<string, number>();
const registeredDevices = new Map<string, RegisteredDevice>();

let grapheneOsAllowlist: GrapheneOsAllowlist | undefined;

/**
 * Gets the GrapheneOS allowlist, creating it on the first call so that the .env file has been loaded.
 * GRAPHENEOS_ALLOWED_SIGNERS optionally overrides the pinned GrapheneOS allowed_signers,
 * e.g. after a key rotation. GRAPHENEOS_ALLOWLIST_CACHE_FILE is optional.
 * @returns the {@link GrapheneOsAllowlist}.
 */
export const getGrapheneOsAllowlist = () => {
  grapheneOsAllowlist ??= new GrapheneOsAllowlist({
    allowedSigners: process.env.GRAPHENEOS_ALLOWED_SIGNERS || undefined,
    cacheFile: process.env.GRAPHENEOS_ALLOWLIST_CACHE_FILE || undefined,
  });
  return grapheneOsAllowlist;
};

/**
 * Builds the options shared by the attestation and the assertion verification from the environment.
 * ANDROID_SIGNATURE_DIGESTS is a comma separated list of the SHA-256 digests of the app signing certificates,
 * which is required to accept devices running GrapheneOS.
 */
const getVerificationOptions = (): AssertionVerificationOptions => ({
  packageNames: [ANDROID_BUNDLE_IDENTIFIER],
  signatureDigests: (process.env.ANDROID_SIGNATURE_DIGESTS ?? '')
    .split(',')
    .map((digest) => digest.trim().replace(/:/g, ''))
    .filter((digest) => digest.length > 0),
  trustedSelfSignedBootKeys: getGrapheneOsAllowlist().getKeys(),
  verifyPlayIntegrity: GOOGLE_APPLICATION_CREDENTIALS
    ? async (integrityToken, requestHash) => {
        const googleCredentials = JSON.parse(GOOGLE_APPLICATION_CREDENTIALS);
        const { data } = await verifyIntegrityToken(
          googleCredentials.client_email,
          googleCredentials.private_key,
          ANDROID_BUNDLE_IDENTIFIER,
          integrityToken
        );
        if (!data.tokenPayloadExternal) {
          throw new Error('Invalid token payload');
        }
        evaluatePlayIntegrityVerdict(data.tokenPayloadExternal, {
          packageName: ANDROID_BUNDLE_IDENTIFIER,
          requestHash,
          requirePlayRecognized:
            process.env.ANDROID_REQUIRE_PLAY_RECOGNIZED === 'true',
        });
      }
    : undefined,
});

/**
 * Consumes a challenge issued by {@link router.get('/nonce')}.
 * @param nonce - The challenge to consume.
 * @returns true if the challenge was issued and not expired, false otherwise.
 */
const consumeNonce = (nonce: unknown) => {
  if (typeof nonce !== 'string') return false;
  const expiresAt = nonces.get(nonce);
  nonces.delete(nonce);
  return expiresAt !== undefined && expiresAt > Date.now();
};

/**
 * Returns a single use challenge to be used for the key attestation or the integrity assertion.
 */
router.get('/nonce', (_, res) => {
  const nonce = uuid();
  nonces.set(nonce, Date.now() + NONCE_VALIDITY_MS);
  res.send({ nonce });
});

/**
 * Verifies a Google Play Integrity Token.
 * The check is done for a standard request and the token is decrypted and verified on Google Cloud, not locally.
 * The GOOGLE_APPLICATION_CREDENTIALS and ANDROID_BUNDLE_IDENTIFIER environment variables must be set.
 * @param integrityToken - The integrity token to verify.
 * @returns The result of the integrity token verification.
 */
router.post('/verifyIntegrityToken', async (req, res) => {
  console.debug(
    `Play integrity verdict was requested: ${JSON.stringify(req.body, null, 2)}`
  );
  if (!GOOGLE_APPLICATION_CREDENTIALS || !ANDROID_BUNDLE_IDENTIFIER) {
    res.status(500).send({
      error:
        'GOOGLE_APPLICATION_CREDENTIALS and ANDROID_BUNDLE_INDENTIFIER must be set in the .env file',
    });
    return;
  }
  try {
    const googleCredentials = JSON.parse(GOOGLE_APPLICATION_CREDENTIALS);
    const { integrityToken } = req.body;
    if (integrityToken === undefined) {
      res.status(400).send({ error: 'Invalid integrity token' });
      return;
    }
    const { data } = await verifyIntegrityToken(
      googleCredentials.client_email,
      googleCredentials.private_key,
      ANDROID_BUNDLE_IDENTIFIER,
      integrityToken
    );
    res.send(data);
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .send({ error: 'An error occurred while verifying the integrity token' });
  }
});

/**
 * Verifies a key attestation which is a signed statement from a secure hardware module that attests to the security properties of the module.
 * On Android it is represented as a chain of X.509 certificates.
 * See {@link verifyAttestation} for more details.
 * When the attestation is valid the device is registered with its hardware key for later assertions.
 * @param attestation - The key attestation to verify
 * @param challenge - The challenge obtained from /nonce and used to generate the attestation
 * @param hardwareKeyTag - The alias of the attested key
 * @returns The result of the chain verification.
 */
router.post('/verifyAttestation', async (req, res) => {
  console.debug(
    `Key attestation verdict was requested: ${JSON.stringify(req.body, null, 2)}`
  );
  try {
    const { attestation, challenge, hardwareKeyTag } = req.body;
    if (typeof hardwareKeyTag !== 'string' || !consumeNonce(challenge)) {
      res.status(400).send({ error: 'Invalid hardware key tag or challenge' });
      return;
    }
    const verified = await verifyAttestation(attestation, {
      ...getVerificationOptions(),
      challenge,
    });
    registeredDevices.set(hardwareKeyTag, verified);
    res.status(200).send({
      result: 'Attestation verified',
      os: verified.os,
      rootOfTrust: verified.record.rootOfTrust,
      osPatchLevel: verified.record.osPatchLevel,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send({
      error: `An error occurred while verifying the key attestation token ${error}`,
    });
  }
});

/**
 * Verifies an integrity assertion of a registered device, see {@link verifyAndroidAssertion}.
 * The client data must be a JSON object which contains a challenge obtained from /nonce.
 * @param hardwareKeyTag - The alias of the key registered with /verifyAttestation
 * @param clientData - The client data signed with the hardware key
 * @param signature - The base64 encoded signature of the client data
 * @param integrityToken - The Play Integrity token, optional
 * @param attestationAssertion - The fresh key attestation, optional
 * @returns The integrity proof which has been accepted.
 */
router.post('/verifyAssertion', async (req, res) => {
  console.debug(
    `Integrity assertion was requested: ${JSON.stringify(req.body, null, 2)}`
  );
  try {
    const {
      hardwareKeyTag,
      clientData,
      signature,
      integrityToken,
      attestationAssertion,
    } = req.body;
    const device = registeredDevices.get(hardwareKeyTag);
    if (!device) {
      res.status(404).send({ error: 'Unknown hardware key tag' });
      return;
    }
    if (
      typeof clientData !== 'string' ||
      !consumeNonce(JSON.parse(clientData).challenge)
    ) {
      res.status(400).send({ error: 'Invalid client data challenge' });
      return;
    }
    const result = await verifyAndroidAssertion(
      device,
      { clientData, signature, integrityToken, attestationAssertion },
      getVerificationOptions()
    );
    res.status(200).send({ result: 'Assertion verified', ...result });
  } catch (error) {
    console.error(error);
    res.status(401).send({
      error: `An error occurred while verifying the integrity assertion ${error}`,
    });
  }
});

export default router;
