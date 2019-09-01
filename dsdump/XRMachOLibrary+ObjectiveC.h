//
//  XRMachOLibrary+ObjectiveC.h
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

#define FILE_OFFSET_UNKNOWN ((intptr_t)-1)

NS_ASSUME_NONNULL_BEGIN




typedef struct  {
    uint16_t mod_off : 16;
    uint16_t mod_len : 16;
    uint16_t cls_off : 16;
    //    uint16_t cls_len : 10;
    BOOL success : 1;
} d_offsets;

// https://github.com/RetVal/objc-runtime/blob/master/runtime/objc-runtime-new.h#L478
#define FAST_IS_SWIFT_LEGACY 1
#define FAST_IS_SWIFT_STABLE 2

BOOL demangleSwiftName(const char *name, d_offsets *f);

@interface XRMachOLibrary (ObjectiveC)

- (void)dumpObjectiveCClasses;
- (void)dumpObjectiveCCategories;



@end

NS_ASSUME_NONNULL_END
