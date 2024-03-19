import { NativeModules, Platform } from 'react-native';
import {
  generateHardwareKey,
  getAttestation,
  isAttestationServiceAvailable,
  generateHardwareSignatureWithAssertion,
} from '..';

jest.mock('react-native', () => ({
  NativeModules: {
    IoReactNativeIntegrity: {
      isAttestationServiceAvailable: jest.fn(),
      generateHardwareKey: jest.fn(),
      getAttestation: jest.fn(),
      generateHardwareSignatureWithAssertion: jest.fn(),
    },
  },
  Platform: {
    select: jest.fn(),
  },
}));

describe('Test integrity check function exposed by main package', () => {
  it('should be called correctly on iOS', async () => {
    Platform.OS = 'ios';

    const spy = jest.spyOn(
      NativeModules.IoReactNativeIntegrity,
      'isAttestationServiceAvailable'
    );

    await isAttestationServiceAvailable();

    expect(spy).toHaveBeenCalled();
  });

  it('should be called correctly on Android', async () => {
    Platform.OS = 'android';

    const spy = jest.spyOn(
      NativeModules.IoReactNativeIntegrity,
      'isAttestationServiceAvailable'
    );

    await isAttestationServiceAvailable();

    expect(spy).toHaveBeenCalled();
  });

  it('generateHardwareKey it should be called correctly', async () => {
    const spy = jest.spyOn(
      NativeModules.IoReactNativeIntegrity,
      'generateHardwareKey'
    );
    await generateHardwareKey();
    expect(spy).toHaveBeenCalled();
  });

  it('getAttestation it should be called correctly', async () => {
    const spy = jest.spyOn(
      NativeModules.IoReactNativeIntegrity,
      'getAttestation'
    );
    await getAttestation('challenge', 'hardwareKeyTag');
    expect(spy).toHaveBeenCalledWith('challenge', 'hardwareKeyTag');
  });

  it('generateHardwareSignatureWithAssertion it should be called correctly', async () => {
    const spy = jest.spyOn(
      NativeModules.IoReactNativeIntegrity,
      'generateHardwareSignatureWithAssertion'
    );
    await generateHardwareSignatureWithAssertion(
      'clientData',
      'hardwareKeyTag'
    );
    expect(spy).toHaveBeenCalledWith('clientData', 'hardwareKeyTag');
  });
});
