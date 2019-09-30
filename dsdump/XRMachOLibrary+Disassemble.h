//
//  XRMachOLibrary+Disassemble.h
//  dsdump
//
//  Created by Derek Selander on 9/27/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <AppKit/AppKit.h>


#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRMachOLibrary (Disassemble)

- (uintptr_t *)resolveMetadataFromCode:(uintptr_t)address;

@end

NS_ASSUME_NONNULL_END
