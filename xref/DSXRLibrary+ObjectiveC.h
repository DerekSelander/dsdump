//
//  DSXRLibrary+ObjectiveC.h
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary.h"

NS_ASSUME_NONNULL_BEGIN

@interface DSXRLibrary (ObjectiveC)
- (void)dumpObjectiveCClasses;
-(const char*)nameForObjCClass:(uintptr_t)address;
@end

NS_ASSUME_NONNULL_END
