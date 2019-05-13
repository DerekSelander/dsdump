//
//  XRMachOLibrary+ObjectiveC.h
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRMachOLibrary (ObjectiveC)
- (void)dumpObjectiveCClasses;
-(const char*)nameForObjCClass:(uintptr_t)address;

#define METHODS_OFFSET_NONE ((intptr_t)-1)
-(intptr_t)methodsOffsetAddressForObjCClass:(uintptr_t)address;
@end

NS_ASSUME_NONNULL_END
