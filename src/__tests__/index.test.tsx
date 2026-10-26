import { NativeModules, Platform } from 'react-native';
import {
  generateHardwareKey,
  getAttestation,
  isAttestationServiceAvailable,
  generateHardwareSignatureWithAssertion,
  isPlayServicesAvailable,
  getHardwareAttestationCapabilities,
  getAttestationAssertion,
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
      getHardwareAttestationCapabilities: jest.fn(),
      getAttestationAssertion: jest.fn(),
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
      expect(spy).toHaveBeenCalledWith('challenge', 'hardwareKeyTag', false);
    });

    it('getAttestation with an attest key it should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'getAttestation'
      );
      await getAttestation('challenge', 'hardwareKeyTag', {
        useAttestKey: true,
      });
      expect(spy).toHaveBeenCalledWith('challenge', 'hardwareKeyTag', true);
    });

    it('getHardwareAttestationCapabilities should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'getHardwareAttestationCapabilities'
      );
      await getHardwareAttestationCapabilities();
      expect(spy).toHaveBeenCalled();
    });

    it('getAttestationAssertion should be called correctly', async () => {
      const spy = jest.spyOn(
        NativeModules.IoReactNativeIntegrity,
        'getAttestationAssertion'
      );
      await getAttestationAssertion('challenge');
      expect(spy).toHaveBeenCalledWith('challenge', null);
      await getAttestationAssertion('challenge', 'hardwareKeyTag');
      expect(spy).toHaveBeenCalledWith('challenge', 'hardwareKeyTag');
    });
  });

  describe('Android only functions on iOS', () => {
    it('getHardwareAttestationCapabilities should reject with PLATFORM_NOT_SUPPORTED', async () => {
      Platform.select = jest
        .fn()
        .mockImplementation((options) => options.ios ?? options.default);
      await expect(getHardwareAttestationCapabilities()).rejects.toEqual({
        message: 'PLATFORM_NOT_SUPPORTED',
        userInfo: {},
      });
    });

    it('getAttestationAssertion should reject with PLATFORM_NOT_SUPPORTED', async () => {
      Platform.select = jest
        .fn()
        .mockImplementation((options) => options.ios ?? options.default);
      await expect(getAttestationAssertion('challenge')).rejects.toEqual({
        message: 'PLATFORM_NOT_SUPPORTED',
        userInfo: {},
      });
    });
  });
});
