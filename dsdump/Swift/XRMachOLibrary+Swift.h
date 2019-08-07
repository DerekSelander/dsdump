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
- (void)dumpSwiftProtocols;
- (void)preparseSwiftProtocols;
@end

#define FAST_IS_SWIFT_LEGACY 1  // < 5
#define FAST_IS_SWIFT_STABLE 2 // 5.X

NS_ASSUME_NONNULL_END
