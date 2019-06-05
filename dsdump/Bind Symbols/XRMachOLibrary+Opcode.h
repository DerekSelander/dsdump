//
//  XRMachOLibrary+Opcode.h
//  xref
//
//  Created by Derek Selander on 4/21/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary.h"

NS_ASSUME_NONNULL_BEGIN


@interface XRMachOLibrary (Opcode)
- (void)parseDYLDExports;
- (void)parseDYLDOpcodes;

@end


NS_ASSUME_NONNULL_END
