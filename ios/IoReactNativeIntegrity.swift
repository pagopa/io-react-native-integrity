import DeviceCheck
import CryptoKit

/// A class to interact with the DeviceCheck and CryptoKit frameworks to ensure the integrity of the device and app.
@objc(IoReactNativeIntegrity)
class IoReactNativeIntegrity: NSObject {
  
  /// Private function to rejects a promise with a specified error.
  /// - Parameters:
  ///   - reject: The promise reject block to call when rejecting a promise.
  ///   - error: The error to use for rejection, providing an error code and message.
  private func rejectPromise(_ reject: @escaping RCTPromiseRejectBlock, withError error: IntegrityError) {
    reject(error.code, error.message, nil)
  }
  
  /// Determines if the DeviceCheck App Attestation Service is available on the device.
  /// - Parameters:
  ///   - resolve: The promise resolve block to call with the result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(isAttestationServiceAvailable:withRejecter:)
  func isAttestationServiceAvailable(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    guard #available(iOS 14.0, *) else {
      self.rejectPromise(reject, withError: .unsupportedIOSVersion)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      resolve(true)
    } else {
      self.rejectPromise(reject, withError: .unsupportedService)
    }
  }
  
  /// Generates a hardware key using the DeviceCheck App Attestation Service.
  /// - Parameters:
  ///   - resolve: The promise resolve block to call with the hardware key tag.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(generateHardwareKey:withRejecter:)
  func generateHardwareKey(resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    
    guard #available(iOS 14.0, *) else {
      self.rejectPromise(reject, withError: .unsupportedIOSVersion)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      service.generateKey { hardwareKeyTag, error in
          
        guard error == nil else {
          self.rejectPromise(reject, withError: .generationKeyFailed)
          return
        }
          
        resolve(hardwareKeyTag)
          
      }
    } else {
      self.rejectPromise(reject, withError: .unsupportedService)
    }
  }
  
  /// Requests an attestation of the hardware key for a given challenge.
  /// - Parameters:
  ///   - challenge: A string representing the challenge for which the attestation is requested.
  ///   - hardwareKeyTag: A string representing the hardware key tag to be attested.
  ///   - resolve: The promise resolve block to call with the attestation result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(getAttestation:withHardwareKeyTag:withResolver:withRejecter:)
  func getAttestation(challenge: String, hardwareKeyTag: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    
    guard #available(iOS 14.0, *) else {
      self.rejectPromise(reject, withError: .unsupportedIOSVersion)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      // Safely encode the challenge string to data and generate a hash.
      guard let challengeData = challenge.data(using: .utf8) else {
          self.rejectPromise(reject, withError: .challengeError)
          return
      }
      let hash = Data(SHA256.hash(data: challengeData))
      
      // Request attestation with the generated hash and handle the response
      service.attestKey(hardwareKeyTag, clientDataHash: hash) {attestation, error in
            
        guard error == nil else {
          self.rejectPromise(reject, withError: .attestationError)
          return
        }
        
        let encodedAttestation = attestation?.base64EncodedString()
          resolve(encodedAttestation)
        }
        
    } else {
      self.rejectPromise(reject, withError: .unsupportedService)
    }
  }
  
  /// Requests an hardwareSignature with assertion for a given clientData and hardwareKeyTag.
  /// - Parameters:
  ///   - clientData: A string representing the clientData (challange+publicJwkEphimeralKey)).
  ///   - hardwareKeyTag: A string representing the hardware key tag to be attested.
  ///   - resolve: The promise resolve block to call with the attestation result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(generateHardwareSignatureWithAssertion:withHardwareKeyTag:withResolver:withRejecter:)
  func generateHardwareSignatureWithAssertion(clientData: String, hardwareKeyTag: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    
    guard #available(iOS 14.0, *) else {
      self.rejectPromise(reject, withError: .unsupportedIOSVersion)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      // Safely encode the clientData string to data and generate a hash.
      guard let encodedClientData = clientData.data(using: .utf8) else {
        self.rejectPromise(reject, withError: .clientDataEncoding)
        return
      }
      
      let clientDataHash = Data(SHA256.hash(data: encodedClientData))
      
      service.generateAssertion(hardwareKeyTag, clientDataHash: clientDataHash) { assertion, error in
        
        guard error == nil else {
          self.rejectPromise(reject, withError: .generationAssertionFailed)
          return
        }
        
        let encodedAssertion = assertion?.base64EncodedString()
        resolve(encodedAssertion)
        
      }
    } else {
      self.rejectPromise(reject, withError: .unsupportedService)
    }
  }
  
}
