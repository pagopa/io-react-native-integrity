#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(IoReactNativeIntegrity, NSObject)

RCT_EXTERN_METHOD(isAttestationServiceAvailable:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateHardwareKey:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getAttestation:(NSString)challenge withHardwareKeyTag:(NSString)hardwareKeyTag
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateHardwareSignatureWithAssertion:(NSString)clientData withHardwareKeyTag:(NSString)hardwareKeyTag
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
