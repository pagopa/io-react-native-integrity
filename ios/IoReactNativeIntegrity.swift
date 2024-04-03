import DeviceCheck
import CryptoKit

/// A class to interact with the DeviceCheck and CryptoKit frameworks to ensure the integrity of the device and app.
@objc(IoReactNativeIntegrity)
class IoReactNativeIntegrity: NSObject {
  private typealias ME = ModuleException
  
  /// Determines if the DeviceCheck App Attestation Service is available on the device.
  /// - Parameters:
  ///   - resolve: The promise resolve block to call with the result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(isAttestationServiceAvailable:withRejecter:)
  func isAttestationServiceAvailable(
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) -> Void {
    guard #available(iOS 14.0, *) else {
      ME.unsupportedService.reject(reject: reject)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      resolve(true)
    } else {
      ME.unsupportedService.reject(reject: reject)
    }
  }
  
  /// Generates a hardware key using the DeviceCheck App Attestation Service.
  /// - Parameters:
  ///   - resolve: The promise resolve block to call with the hardware key tag.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(generateHardwareKey:withRejecter:)
  func generateHardwareKey(
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) -> Void {
    
    guard #available(iOS 14.0, *) else {
      ME.unsupportedIOSVersion.reject(reject: reject)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      service.generateKey { hardwareKeyTag, error in
        
        guard error == nil else {
          ME.generationKeyFailed.reject(reject: reject, ("error", error?.localizedDescription ?? ""))
          return
        }
        
        resolve(hardwareKeyTag)
        
      }
    } else {
      ME.unsupportedService.reject(reject: reject);
    }
  }
  
  /// Requests an attestation of the hardware key for a given challenge.
  /// - Parameters:
  ///   - challenge: A string representing the challenge for which the attestation is requested.
  ///   - hardwareKeyTag: A string representing the hardware key tag to be attested.
  ///   - resolve: The promise resolve block to call with the attestation result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(getAttestation:withHardwareKeyTag:withResolver:withRejecter:)
  func getAttestation(
    challenge: String,
    hardwareKeyTag: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) -> Void {
    
    guard #available(iOS 14.0, *) else {
      ME.unsupportedIOSVersion.reject(reject: reject);
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      // Safely encode the challenge string to data and generate a hash.
      guard let challengeData = challenge.data(using: .utf8) else {
        ME.challengeError.reject(reject: reject)
        return
      }
      let hash = Data(SHA256.hash(data: challengeData))
      
      // Request attestation with the generated hash and handle the response
      service.attestKey(hardwareKeyTag, clientDataHash: hash) {attestation, error in
        
        guard error == nil else {
          ME.attestationError.reject(reject: reject, ("error", error?.localizedDescription ?? ""))
          return
        }
        
        let encodedAttestation = attestation?.base64EncodedString()
        resolve(encodedAttestation)
      }
      
    } else {
      ME.unsupportedService.reject(reject: reject)
    }
  }
  
  /// Requests an hardwareSignature with assertion for a given clientData and hardwareKeyTag.
  /// - Parameters:
  ///   - clientData: A string representing the clientData (challange+publicJwkEphimeralKey)).
  ///   - hardwareKeyTag: A string representing the hardware key tag to be attested.
  ///   - resolve: The promise resolve block to call with the attestation result.
  ///   - reject: The promise reject block to call in case of an error.
  @objc(generateHardwareSignatureWithAssertion:withHardwareKeyTag:withResolver:withRejecter:)
  func generateHardwareSignatureWithAssertion(
    clientData: String,
    hardwareKeyTag: String,
    resolve: @escaping RCTPromiseResolveBlock,
    reject: @escaping RCTPromiseRejectBlock
  ) -> Void {
    
    guard #available(iOS 14.0, *) else {
      ME.unsupportedIOSVersion.reject(reject: reject)
      return
    }
    
    if DCAppAttestService.shared.isSupported {
      let service = DCAppAttestService.shared
      
      // Safely encode the clientData string to data and generate a hash.
      guard let encodedClientData = clientData.data(using: .utf8) else {
        ME.clientDataEncodingError.reject(reject: reject)
        return
      }
      
      let clientDataHash = Data(SHA256.hash(data: encodedClientData))
      
      service.generateAssertion(hardwareKeyTag, clientDataHash: clientDataHash) { assertion, error in
        
        guard error == nil else {
          ME.generationAssertionFailed.reject(reject: reject, ("error", error?.localizedDescription ?? ""))
          return
        }
        
        let encodedAssertion = assertion?.base64EncodedString()
        resolve(encodedAssertion)
        
      }
    } else {
      ME.unsupportedService.reject(reject: reject)
    }
  }
  
  /// A private enum to handle exceptions and errors.
  /// - generationKeyFailed: The hardware key generation failed.
  /// - unsupportedService: The DeviceCheck App Attestation Service is not supported.
  /// - attestationError: The attestation request failed.
  /// - unsupportedIOSVersion: The iOS version is not supported.
  /// - challengeError: The challenge encoding failed.
  /// - clientDataEncodingError: The clientData encoding failed.
  /// - generationAssertionFailed: The assertion generation failed.
  private enum ModuleException: String, CaseIterable {
    
    case generationKeyFailed = "GENERATION_KEY_FAILED"
    case unsupportedService = "UNSUPPORTED_SERVICE"
    case attestationError = "ATTESTATION_ERROR"
    case unsupportedIOSVersion = "UNSUPPORTED_IOS_VERSION"
    case challengeError = "CHALLANGE_ERROR"
    case clientDataEncodingError = "CLIENT_DATA_ENCODING_ERROR"
    case generationAssertionFailed = "GENERATION_ASSERTION_FAILED"
    
    func error(userInfo: [String : Any]? = nil) -> NSError {
      switch self {
      case .generationKeyFailed:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .unsupportedService:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .attestationError:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .unsupportedIOSVersion:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .challengeError:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .clientDataEncodingError:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      case .generationAssertionFailed:
        return NSError(domain: self.rawValue, code: -1, userInfo: userInfo)
      }
    }
    
    /// Rejects a promise with the error.
    /// - Parameters:
    ///  - reject: The promise reject block to call in case of an error.
    ///  - moreUserInfo: A list of tuples to add more information to the error.
    func reject(reject: RCTPromiseRejectBlock, _ moreUserInfo: (String, Any)...) {
      var userInfo = [String : Any]()
      moreUserInfo.forEach { userInfo[$0.0] = $0.1 }
      let error = error(userInfo: userInfo)
      reject("\(error.code)", error.domain, error)
    }
  }
}
