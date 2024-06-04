import { NativeModules, Platform } from 'react-native';

/**
 * ANDROID ONLY
 * Error codes returned by the Android module.
 */
type IntegrityErrorCodesAndroid =
  | 'WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT'
  | 'PREPARE_FAILED'
  | 'PREPARE_NOT_CALLED'
  | 'REQUEST_TOKEN_FAILED'
  | 'REQUEST_ATTESTATION_FAILED'
  | 'KEY_IS_NOT_HARDWARE_BACKED'
  | 'UNSUPPORTED_DEVICE'
  | 'KEYSTORE_NOT_INITIALIZED';

/**
 * Error codes returned by the iOS module.
 */
type IntegrityErrorCodesIOS =
  | 'GENERATION_KEY_FAILED'
  | 'UNSUPPORTED_SERVICE'
  | 'ATTESTATION_ERROR'
  | 'UNSUPPORTED_IOS_VERSION'
  | 'CHALLANGE_ERROR'
  | 'CLIENT_DATA_ENCODING_ERROR'
  | 'GENERATION_ASSERTION_FAILED'
  | 'DECODING_ASSERTION_FAILED';

type IntegrityErrorCodesCommon = 'PLATFORM_NOT_SUPPORTED';

export type IntegrityErrorCodes =
  | IntegrityErrorCodesIOS
  | IntegrityErrorCodesAndroid
  | IntegrityErrorCodesCommon;

/**
 * Error type returned by a rejected promise.
 *
 * If additional error information are available,
 * they are stored in the {@link IntegrityError["userInfo"]} field.
 */
export type IntegrityError = {
  message: IntegrityErrorCodes;
  userInfo: Record<string, string>;
};

/**
 * Tpye of the decoded attestation.
 * Both signature and authenticatorData are base64 encoded.
 */
export type DecodedAttestation = {
  signature: string;
  authenticatorData: string;
};

/**
 * Error when the platform is not supported.
 */
const IntegrityErrorUnsupportedError: IntegrityError = {
  message: 'PLATFORM_NOT_SUPPORTED',
  userInfo: {},
};

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
 * iOS ONLY
 * This function checks if the attestation service is available on the device.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @returns a promise that resolves to a boolean.
 */
export function isAttestationServiceAvailable(): Promise<boolean> {
  return Platform.select({
    ios: () => IoReactNativeIntegrity.isAttestationServiceAvailable(),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * iOS ONLY
 * This function generates a hardware key that can be used into the attestation process.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @returns a promise that resolves to a string.
 */
export function generateHardwareKey(): Promise<string> {
  return Platform.select({
    ios: () => IoReactNativeIntegrity.generateHardwareKey(),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * iOS ONLY
 * This function generates an attestation for the given challenge and hardware key.
 *
 * If it is not possible to retrive the attestation, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @param challenge challange to be used in the attestation process returned byt a backend service
 * @param hardwareKeyTag hardware key to be used in the attestation process
 * @returns a promise that resolves to a string.
 */
export function getAttestation(
  challenge: string,
  hardwareKeyTag: string
): Promise<string> {
  return Platform.select({
    ios: () => IoReactNativeIntegrity.getAttestation(challenge, hardwareKeyTag),
    android: () =>
      IoReactNativeIntegrity.getAttestation(challenge, hardwareKeyTag),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * iOS ONLY
 * This function generates a signature for the given client data given an hardware key.
 *
 * If it is not possible to retrive the signature, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @param clientData client data to be signed
 * @param hardwareKeyTag hardware key to be used in the signature process
 * @returns a promise that resolves to a string.
 */
export function generateHardwareSignatureWithAssertion(
  clientData: string,
  hardwareKeyTag: string
): Promise<string> {
  return Platform.select({
    ios: () =>
      IoReactNativeIntegrity.generateHardwareSignatureWithAssertion(
        clientData,
        hardwareKeyTag
      ),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * This function decodes a CBOR encoded iOS assertion.
 *
 * If it is not possible to decode the assertion, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @param assertion - the CBOR assertion to be decoded
 * @returns - a promise that resolves to a {@link DecodedAttestation} which contains base64 encoded signature and authenticatorData.
 */
export function decodeAssertion(
  assertion: string
): Promise<DecodedAttestation> {
  return IoReactNativeIntegrity.decodeAssertion(assertion);
}

/**
 * ANDROID ONLY
 * Checks whether Google Play Services is available on the device or not.
 * @return a promise resolved to true if Google Play Services is available, to false otherwise.
 */
export function isPlayServicesAvailable(): Promise<boolean> {
  return Platform.select({
    android: () => IoReactNativeIntegrity.isPlayServicesAvailable(),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * ANDROID ONLY
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
  return Platform.select({
    android: () =>
      IoReactNativeIntegrity.prepareIntegrityToken(cloudProjectNumber),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}

/**
 * ANDROID ONLY
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
  return Platform.select({
    android: () => IoReactNativeIntegrity.requestIntegrityToken(requestHash),
    default: () => Promise.reject(IntegrityErrorUnsupportedError),
  })();
}
