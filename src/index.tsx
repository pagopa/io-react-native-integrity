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

export function multiply(a: number, b: number): Promise<number> {
  return IoReactNativeIntegrity.multiply(a, b);
}

export function isPlayServicesAvailable(): Promise<boolean> {
  return IoReactNativeIntegrity.isPlayServicesAvailable();
}

export function prepare(cloudProjectNumber: string): Promise<void> {
  return IoReactNativeIntegrity.prepare(cloudProjectNumber);
}

export function requestToken(requestHash?: string): Promise<string> {
  return IoReactNativeIntegrity.requestToken(requestHash);
}
type IntegrityErrorCodesAndroid =
  | 'WRONG_GOOGLE_CLOUD_PROJECT_NUMBER_FORMAT'
  | 'PREPARE_FAILED'
  | 'PREPARE_NOT_CALLED'
  | 'REQUEST_TOKEN_FAILED';

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
