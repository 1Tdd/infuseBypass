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
    }
    return 0;
}
