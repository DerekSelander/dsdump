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

// OffsetType used in
typedef enum {
    OffSetTypeIvar,
    OffSetTypeMethods,
    OffSetTypeProperties
} OffSetType;


typedef struct  {
    uint16_t mod_off : 16;
    uint16_t mod_len : 16;
    uint16_t cls_off : 16;
    //    uint16_t cls_len : 10;
    BOOL success : 1;
} d_offsets;

BOOL demangleSwiftName(const char *name, d_offsets *f);

@interface XRMachOLibrary (ObjectiveC)
- (void)dumpObjectiveCClasses;
-(const char*)nameForObjCClass:(uintptr_t)address;

-(intptr_t)offsetAddressForObjCClass:(uintptr_t)address forType:(OffSetType)offsetType;
@end

NS_ASSUME_NONNULL_END
