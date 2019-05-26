//
//  XRMachOLibrary+ObjectiveC.h
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

typedef enum {
    OffSetTypeIvar,
    OffSetTypeMethods,
    OffSetTypeProperties
} OffSetType;

@interface XRMachOLibrary (ObjectiveC)
- (void)dumpObjectiveCClasses;
-(const char*)nameForObjCClass:(uintptr_t)address;

#define FILE_OFFSET_UNKNOWN ((intptr_t)-1)

@end

NS_ASSUME_NONNULL_END
