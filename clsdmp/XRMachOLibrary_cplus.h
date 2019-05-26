//
//  XRMachOLibrary_cplus.h
//  xref
//
//  Created by Derek Selander on 5/21/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#ifndef XRMachOLibrary_cplus_h
#define XRMachOLibrary_cplus_h

#import "XRMachOLibrary.h"
#import <unordered_map>

// Dealing with the c++
@interface XRMachOLibrary (Opcode_Private)
@property (nonatomic, assign) std::unordered_map<uint64_t, XRSymbolEntry*> exports;
@end

@implementation XRMachOLibrary (Opcode_Private)
@dynamic exports; // Defined in XRMachOLibrary.mm
@end

#endif /* XRMachOLibrary_cplus_h */
