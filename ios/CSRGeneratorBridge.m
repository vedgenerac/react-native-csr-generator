#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(CSRGenerator, NSObject)

RCT_EXTERN_METHOD(generateECCKeyPair:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(generateCSR:(NSString *)cn
                  userId:(NSString *)userId
                  country:(NSString *)country
                  state:(NSString *)state
                  locality:(NSString *)locality
                  organization:(NSString *)organization
                  organizationalUnit:(NSString *)organizationalUnit
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end