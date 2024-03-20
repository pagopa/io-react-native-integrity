import { google } from 'googleapis';

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
