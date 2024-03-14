import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package '@pagopa/io-react-native-integrity' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const IoReactNativeIntegrity = NativeModules.IoReactNativeIntegrity
  ? NativeModules.IoReactNativeIntegrity
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

/**
 * Checks whether Google Play Services is available on the device or not.
 * @return a promise resolved to true if Google Play Services is available, to false otherwise.
 */
export function isPlayServicesAvailable(): Promise<boolean> {
  return IoReactNativeIntegrity.isPlayServicesAvailable();
}

/**
 * Preparation step for a [Play Integrity standard API request](https://developer.android.com/google/play/integrity/standard).
 * It prepares the integrity token provider before obtaining the integrity verdict.
 * It should be called well before the moment an integrity verdict is needed, for example
 * when starting the application. It can also be called time to time to refresh it.
 * it gets rejected when:
 * - The preparation fails;
 * - The provided [cloudProjectNumber] format is incorrect.
 * @param cloudProjectNumber a Google Cloud project number which is supposed to be composed only by numbers.
 * @return a resolved promise when the preparation is successful, rejected otherwise when:
 * - The preparation fails or;
 * - The provided cloudProjectNumber format is incorrect.
 */
export function prepareIntegrityToken(
  cloudProjectNumber: string
): Promise<void> {
  return IoReactNativeIntegrity.prepareIntegrityToken(cloudProjectNumber);
}

/**
 * Integrity token request step for a [Play Integrity standard API request](https://developer.android.com/google/play/integrity/standard).
 * It requests an integrity token which is then attached to the request to be protected.
 * It should be called AFTER {@link prepareIntegrityToken} has been called and resolved successfully.
 * The React Native
 * @param requestHash a digest of all relevant request parameters (e.g. SHA256) from the user action or server request that is happening.
 * The max size of this field is 500 bytes. Do not put sensitive information as plain text in this field.
 * @returns a resolved promise with with the token as payload, rejected otherwise when:
 * - The integrity token request fails;
 * - The {@link prepareIntegrityToken} function hasn't been called previously.
 */
export function requestIntegrityToken(requestHash?: string): Promise<string> {
  return IoReactNativeIntegrity.requestIntegrityToken(requestHash);
}

/**
 * Generates a (Key Attestation)[https://developer.android.com/privacy-and-security/security-key-attestation].
 * During key attestation, a key pair is generated along with its certificate chain,
 * which can be used to verify the properties of that key pair.
 * If the device supports hardware-level key attestation,
 * the root certificate of the chain is signed using an attestation root key
 * protected by the device's hardware-backed keystore.
 * @param challenge the challenge to be included which has a max size of 128 bytes.
 * @param keyAlias optional key alias for the generated key pair.
 * @returns a resolved promise with the attestation chain as payload, rejected otherwise when:
 * - The device doesn't support key attestation;
 * - The generated key pair is not hardware backed;
 * - The [challenge] exceeds the size of 128 bytes;
 * - The key attestation generation fails.
 */
export function getAttestation(
  challenge: string,
  keyAlias?: string
): Promise<string> {
  return IoReactNativeIntegrity.getAttestation(challenge, keyAlias);
}

/**
 * Possible error codes returned by the library on Android when a promise is rejected.
 */
type IntegrityErrorCodesAndroid =
  | 'WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT'
  | 'PREPARE_FAILED'
  | 'PREPARE_NOT_CALLED'
  | 'REQUEST_TOKEN_FAILED'
  | 'REQUEST_ATTESTATION_FAILED'
  | 'KEY_IS_NOT_HARDWARE_BACKED'
  | 'UNSUPPORTED_DEVICE';

/**
 * Type of the error codes returned by the library when a promise is rejected.
 * It should be a union of Android and iOS error codes.
 */
export type IntegrityErrorCodes = IntegrityErrorCodesAndroid;

/**
 * Error type returned by a rejected promise.
 *
 * If additional error information are available,
 * they are stored in the {@link CryptoError["info"]} field.
 */
export type IntegrityError = {
  message: IntegrityErrorCodes;
  info: Record<string, string>;
};
