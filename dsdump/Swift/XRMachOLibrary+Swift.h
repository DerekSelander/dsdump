//
//  XRMachOLibrary+Swift.h
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRMachOLibrary (Swift)

- (void)dumpSwiftTypes;
- (BOOL)preparseSwiftTypes;
@end

#define Resolve32BitAddress(addr) *(uint32_t *)(DATABUF([self translateLoadAddressToFileOffset:(uintptr_t)(addr) useFatOffset:YES]))

#define Resolve64BitAddress(addr) *(uint64_t *)(DATABUF([self translateLoadAddressToFileOffset:(uintptr_t)(addr) useFatOffset:YES]))

NS_ASSUME_NONNULL_END
