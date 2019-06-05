//
//  XRMachOLibrary+Dump.h
//  xref
//
//  Created by Derek Selander on 5/11/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface XRMachOLibrary (Dump)

- (void)dumpFileOffset:(off_t)offset count:(uint8_t)count grouping:(uint8_t)grouping format:(char)format;

@end

NS_ASSUME_NONNULL_END
