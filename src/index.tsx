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

export function isAttestationServiceAvailable(): Promise<boolean> {
  return IoReactNativeIntegrity.isAttestationServiceAvailable();
}

export function generateHardwareKey(): Promise<string> {
  return IoReactNativeIntegrity.generateHardwareKey();
}

export function getAttestation(
  challenge: string,
  hardwareKeyTag: string
): Promise<string> {
  return IoReactNativeIntegrity.getAttestation(challenge, hardwareKeyTag);
}

export function generateHardwareSignatureWithAssertion(
  clientData: string,
  hardwareKeyTag: string
): Promise<string> {
  return IoReactNativeIntegrity.generateHardwareSignatureWithAssertion(
    clientData,
    hardwareKeyTag
  );
}
