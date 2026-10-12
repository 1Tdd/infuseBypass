//
//  InfuseBypass.m
//  InfuseBypass
//
//  Created by tylinux on 2025/12/27.
//
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <strings.h>

@interface InfuseBypass : NSObject
@end

// Install each replacement independently. Exchanging the same replacement
// twice makes the second target receive the first target's original method.
static void IBReplaceMethod(Class target, SEL selector, Class replacementClass, SEL replacementSelector) {
    Method original = class_getInstanceMethod(target, selector);
    Method replacement = class_getInstanceMethod(replacementClass, replacementSelector);
    if (!original || !replacement) {
        return;
    }
    // Adding first also avoids changing a superclass's inherited method.
    IMP implementation = method_getImplementation(replacement);
    const char *encoding = method_getTypeEncoding(original);
    if (!class_addMethod(target, selector, implementation, encoding)) {
        class_replaceMethod(target, selector, implementation, encoding);
    }
}

@implementation InfuseBypass

+ (void)load {
    NSLog(@"Infuse Bypass init");
    Class HookClass = InfuseBypass.class;
    // Hook -[FCInAppPurchaseServiceFreemium iapVersionStatus]
    Class iapClass = objc_getClass("FCInAppPurchaseServiceFreemium");
    Method originalIapMethod = class_getInstanceMethod(iapClass, NSSelectorFromString(@"iapVersionStatus"));
    Method swizzledIapMethod = class_getInstanceMethod(HookClass, @selector(returnTrue));

    if (originalIapMethod && swizzledIapMethod) {
        IBReplaceMethod(iapClass, NSSelectorFromString(@"iapVersionStatus"), HookClass, @selector(returnTrue));
    }

    // Hook Swift -[Infuse.InAppPurchaseServiceFreemiumSK2 iapVersionStatus]
    Class swiftIapClass = objc_getClass("_TtC6infuse31InAppPurchaseServiceFreemiumSK2");
    Method originalSwiftIapMethod = class_getInstanceMethod(swiftIapClass, NSSelectorFromString(@"iapVersionStatus"));
    Method swizzledSwiftIapMethod = class_getInstanceMethod(HookClass, @selector(returnTrue));

    if (originalSwiftIapMethod && swizzledSwiftIapMethod) {
        IBReplaceMethod(swiftIapClass, NSSelectorFromString(@"iapVersionStatus"), HookClass, @selector(returnTrue));
    }

    // Hook -[Infuse.InAppPurchaseServiceFreemiumSK2 isFeaturePurchased:tillDate:]
    Method originalSK2PurchaseMethod = class_getInstanceMethod(swiftIapClass, @selector(isFeaturePurchased:tillDate:));
    Method swizzledSK2PurchaseMethod = class_getInstanceMethod(HookClass, @selector(isFeaturePurchased:tillDate:));

    if (originalSK2PurchaseMethod && swizzledSK2PurchaseMethod) {
        IBReplaceMethod(swiftIapClass, @selector(isFeaturePurchased:tillDate:), HookClass, @selector(isFeaturePurchased:tillDate:));
    }

    // Hook NSFileManager containerURLForSecurityApplicationGroupIdentifier:
    Class fileManagerClass = objc_getClass("NSFileManager");
    Method originalFMMethod = class_getInstanceMethod(fileManagerClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    Method swizzledFMMethod = class_getInstanceMethod(HookClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));

    if (originalFMMethod && swizzledFMMethod) {
        IBReplaceMethod(fileManagerClass, @selector(containerURLForSecurityApplicationGroupIdentifier:), HookClass, @selector(containerURLForSecurityApplicationGroupIdentifier:));
    }
    // Hook CKContainer defaultContainer
    Class cloudKitClass = objc_getClass("CKContainer");
    Method originalDefaultMethod = class_getClassMethod(cloudKitClass, @selector(defaultContainer));
    Method swizzledDefaultMethod = class_getClassMethod(HookClass, @selector(defaultContainer));

    if (originalDefaultMethod && swizzledDefaultMethod) {
        IBReplaceMethod(object_getClass(cloudKitClass), @selector(defaultContainer), object_getClass(HookClass), @selector(defaultContainer));
    }

    // Hook CKContainer containerWithIdentifier:
    Method originalIdentifierMethod = class_getClassMethod(cloudKitClass, @selector(containerWithIdentifier:));
    Method swizzledIdentifierMethod = class_getClassMethod(HookClass, @selector(containerWithIdentifier:));

    if (originalIdentifierMethod && swizzledIdentifierMethod) {
        IBReplaceMethod(object_getClass(cloudKitClass), @selector(containerWithIdentifier:), object_getClass(HookClass), @selector(containerWithIdentifier:));
    }
}

- (BOOL)returnTrue {
    return YES;
}
- (BOOL)isFeaturePurchased:(long long)purchased tillDate:(id *)date {
    return YES;
}
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    if (!groupIdentifier.length || [groupIdentifier containsString:@"/"] ||
        [groupIdentifier isEqualToString:@"."] || [groupIdentifier isEqualToString:@".."]) {
        return nil;
    }
    // tvOS supports local cache storage; Documents is not writable on older tvOS.
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *cacheURL = [[fileManager URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask] firstObject];
    if (!cacheURL) {
        return nil;
    }
    NSURL *baseURL = [cacheURL URLByAppendingPathComponent:@"ApplicationGroupContainers" isDirectory:YES];
    NSURL *containerURL = [baseURL URLByAppendingPathComponent:groupIdentifier];
    // Recreate individual subdirectories even if tvOS purged only part of a cache.
    for (NSString *directory in @[@"", @"Library/Application Support", @"Library/Caches", @"Library/Preferences"]) {
        NSURL *directoryURL = directory.length ? [containerURL URLByAppendingPathComponent:directory] : containerURL;
        NSError *error = nil;
        if (![fileManager createDirectoryAtURL:directoryURL withIntermediateDirectories:YES attributes:nil error:&error]) {
            NSLog(@"Infuse Bypass could not create local app-group storage: %@", error);
            return nil;
        }
    }
    return containerURL;
}
+ (id)defaultContainer {
    return nil;
}
+ (id)containerWithIdentifier:(NSString *)identifier {
    return nil;
}

@end
