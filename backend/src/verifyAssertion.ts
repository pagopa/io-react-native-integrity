import { createHash, createVerify } from 'crypto';

export type VerifyAssertionParams = {
  signature: string;
  authenticatorData: string;
  payload: Buffer;
  publicKey: string;
  bundleIdentifier: string;
  teamIdentifier: string;
  signCount: number;
};

/**
 * A function to verify an assertion from a hardware key.
 * @param params
 * @returns
 */
const verifyAssertion = (params: VerifyAssertionParams) => {
  const {
    signature,
    authenticatorData,
    payload,
    publicKey,
    bundleIdentifier,
    teamIdentifier,
    signCount,
  } = params;

  if (!bundleIdentifier) {
    throw new Error('bundleIdentifier is required');
  }

  if (!teamIdentifier) {
    throw new Error('teamIdentifier is required');
  }

  if (!signature) {
    throw new Error('signature is required');
  }

  if (!authenticatorData) {
    throw new Error('authenticatorData is required');
  }

  if (!payload) {
    throw new Error('payload is required');
  }

  if (!publicKey) {
    throw new Error('publicKey is required');
  }

  const sign = Buffer.from(signature, 'base64');
  const authData = Buffer.from(authenticatorData, 'base64');
  // 2. Compute the SHA256 hash of the client data, and store it as clientDataHash.
  const clientDataHash = createHash('sha256').update(payload).digest();

  // 3. Compute the SHA256 hash of the concatenation of the authenticator
  // data and the client data hash, and store it as nonce.
  const nonce = createHash('sha256')
    .update(Buffer.concat([authData, clientDataHash]))
    .digest();

  // 4. Verify the signature using the public key and nonce.
  const verifier = createVerify('SHA256');
  verifier.update(nonce);
  if (!verifier.verify(publicKey, sign)) {
    throw new Error('invalid signature');
  }

  // 5. Compute the SHA256 hash of your app’s App ID, and verify that it’s the same as the authenticator data’s RP ID hash.
  const appIdHash = createHash('sha256')
    .update(`${teamIdentifier}.${bundleIdentifier}`)
    .digest('base64');
  const rpiIdHash = authData.subarray(0, 32).toString('base64');

  if (appIdHash !== rpiIdHash) {
    throw new Error('appId does not match');
  }

  // 6. Verify that the authenticator data’s counter field is larger than the stored signCount.
  const nextSignCount = authData.subarray(33, 37).readInt32BE();
  if (nextSignCount <= signCount) {
    throw new Error('invalid signCount');
  }

  return { signCount: nextSignCount };
};

export default verifyAssertion;
