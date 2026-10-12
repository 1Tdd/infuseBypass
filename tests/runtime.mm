#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <assert.h>
#import "../InfuseBypass/InfuseBypass.mm"

static BOOL originallyFalse(id self, SEL selector) { return NO; }

int main() {
    @autoreleasepool {
        // Create both classes, then install the hooks together. The previous
        // double exchange made the Swift class call originallyFalse.
        const char *names[] = {"FCInAppPurchaseServiceFreemium", "_TtC6infuse31InAppPurchaseServiceFreemiumSK2"};
        for (const char *name : names) {
            Class cls = objc_allocateClassPair(NSObject.class, name, 0);
            assert(cls);
            class_addMethod(cls, sel_registerName("iapVersionStatus"), (IMP)originallyFalse, "c@:");
            objc_registerClassPair(cls);
        }
        [InfuseBypass load];
        [InfuseBypass load]; // Repeated installation must remain safe.
        for (const char *name : names) {
            id object = [objc_getClass(name) new];
            BOOL result = ((BOOL (*)(id, SEL))objc_msgSend)(object, sel_registerName("iapVersionStatus"));
            assert(result == YES);
        }
        NSLog(@"Both independent purchase hooks passed");
        NSFileManager *manager = NSFileManager.defaultManager;
        NSString *group = [@"group.infusebypass.test." stringByAppendingString:NSUUID.UUID.UUIDString];
        NSURL *container = [manager containerURLForSecurityApplicationGroupIdentifier:group];
        assert(container);
        for (NSString *directory in @[@"Library/Application Support", @"Library/Caches", @"Library/Preferences"]) {
            assert([manager fileExistsAtPath:[[container URLByAppendingPathComponent:directory] path]]);
        }
        NSURL *cache = [container URLByAppendingPathComponent:@"Library/Caches"];
        assert([manager removeItemAtURL:cache error:nil]);
        assert([manager containerURLForSecurityApplicationGroupIdentifier:group]);
        assert([manager fileExistsAtPath:cache.path]);
        assert([manager containerURLForSecurityApplicationGroupIdentifier:@"../escape"] == nil);
        assert([manager removeItemAtURL:container error:nil]);
        NSLog(@"Local cache storage and partial-directory recreation passed");
    }
    return 0;
}
