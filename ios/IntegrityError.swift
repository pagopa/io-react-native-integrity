//
//  IntegrityError.swift
//  pagopa-io-react-native-integrity
//
//  Created by Mario Perrotta on 07/03/24.
//

enum IntegrityError: Error {
    case generationKeyFailed
    case unsupportedService
    case attestationError
    case unsupportedIOSVersion
    case challengeError
    case clientDataEncoding
    case generationAssertionFailed
    
    var code: String {
        switch self {
          case .generationKeyFailed:
              return "generation_key_failed"
          case .unsupportedService:
              return "unsupported_service"
          case .attestationError:
              return "attestation_error"
          case .unsupportedIOSVersion:
              return "unsupported_ios_version"
          case .challengeError:
              return "challenge_error"
          case .clientDataEncoding:
              return "client_data_encoding_error"
          case .generationAssertionFailed:
              return "generation_assertion_failed"
        }
    }
    
    var message: String {
        switch self {
          case .generationKeyFailed:
              return "Generation key failed."
          case .unsupportedService:
              return "Unsupported service."
          case .attestationError:
              return "Attestation error during generation."
          case .unsupportedIOSVersion:
              return "App attest service requires iOS 14 or above."
          case .challengeError:
              return "Error getting challenge data"
          case .clientDataEncoding:
              return "Error encoding client data"
          case .generationAssertionFailed:
              return "Generation Assertion failed"
        }
    }
}
