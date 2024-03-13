import { NativeModules, Platform } from 'react-native';

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
  | 'GENERATION_ASSERTION_FAILED';

export type IntegrityErrorCodes = IntegrityErrorCodesIOS;

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
 * This function checks if the attestation service is available on the device.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @returns a promise that resolves to a boolean.
 */
export function isAttestationServiceAvailable(): Promise<boolean> {
  return IoReactNativeIntegrity.isAttestationServiceAvailable();
}

/**
 * This function generates a hardware key that can be used into the attestation process.
 *
 * If it is not possible to retrive the key, the promise is rejected providing an
 * instance of {@link IntegrityError}.
 *
 * @returns a promise that resolves to a string.
 */
export function generateHardwareKey(): Promise<string> {
  return IoReactNativeIntegrity.generateHardwareKey();
}

/**
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
  return IoReactNativeIntegrity.getAttestation(challenge, hardwareKeyTag);
}

/**
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
  return IoReactNativeIntegrity.generateHardwareSignatureWithAssertion(
    clientData,
    hardwareKeyTag
  );
}
