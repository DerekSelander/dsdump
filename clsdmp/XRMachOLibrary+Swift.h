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

/// F it, I am using Apple's demangler since they change their mangling too much
- (BOOL)loadSwiftDemangle;
@end

NS_ASSUME_NONNULL_END
