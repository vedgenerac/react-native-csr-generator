#import "CSRGeneratorModule.h"
#import <React/RCTLog.h>
#import "GeneracHome-Swift.h"

@implementation CSRGeneratorModule

RCT_EXPORT_MODULE();

RCT_EXPORT_METHOD(generateCSR:(NSDictionary *)subjectInfo
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)
{
    @try {
        CSRGenerator *csrGenerator = [[CSRGenerator alloc] init];
        NSError *error;
        NSString *csrPem = [csrGenerator generateCSRWithSubjectInfo:subjectInfo error:&error];
        
        if (error || !csrPem) {
            reject(@"CSRGenerationError", error.localizedDescription ?: @"Failed to generate CSR", error);
            return;
        }
        
        resolve(csrPem);
    } @catch (NSException *exception) {
        reject(@"CSRGenerationException", exception.reason, nil);
    }
}

@end