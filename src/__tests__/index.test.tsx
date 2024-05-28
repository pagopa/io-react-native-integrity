import { NativeModules, Platform } from 'react-native';
import {
  generateHardwareKey,
  getAttestation,
  isAttestationServiceAvailable,
  generateHardwareSignatureWithAssertion,
  isPlayServicesAvailable,
  prepareIntegrityToken,
  requestIntegrityToken,
} from '..';

jest.mock('react-native', () => ({
  NativeModules: {
    IoReactNativeIntegrity: {
      isAttestationServiceAvailable: jest.fn(),
      generateHardwareKey: jest.fn(),
      getAttestation: jest.fn(),
      generateHardwareSignatureWithAssertion: jest.fn(),
      requestIntegrityToken: jest.fn(),
      prepareIntegrityToken: jest.fn(),
      isPlayServicesAvailable: jest.fn(),
    },
  },
  Platform: {
    select: jest.fn(),
  },
}));

const mockPlatformiOS = () =>
  (Platform.select = jest.fn().mockImplementation((options) => options.ios));

const mockPlatformAndroid = () =>
  (Platform.select = jest
    .fn()
    .mockImplementation((options) => options.android));

describe('Test integrity check function exposed by main package', () => {
  describe('iOS functions', () => {
    beforeAll(() => {
      mockPlatformiOS();
    });

    it('isAttestationServiceAvailable should be called correctly', async () => {
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

  describe('Android functions', () => {
    beforeAll(() => {
      mockPlatformAndroid();
    });

    it('isPlayServicesAvailable should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'isPlayServicesAvailable'
      );

      await isPlayServicesAvailable();

      expect(spy).toHaveBeenCalled();
    });

    it('prepareIntegrityToken should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'prepareIntegrityToken'
      );

      await prepareIntegrityToken('cloudProjectNumber');

      expect(spy).toHaveBeenCalledWith('cloudProjectNumber');
    });

    it('requestIntegrityToken should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'requestIntegrityToken'
      );
      await requestIntegrityToken('requestHash');
      expect(spy).toHaveBeenCalledWith('requestHash');
    });

    it('getAttestation it should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'getAttestation'
      );
      await getAttestation('challenge', 'hardwareKeyTag');
      expect(spy).toHaveBeenCalledWith('challenge', 'hardwareKeyTag');
    });
  });
});
