//
//  Methods.hpp
//  dsdump
//
//  Created by Derek Selander on 4/29/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#ifndef Methods_hpp
#define Methods_hpp

#import <stdio.h>
#import "string.h"
#import "XRMachOLibrary+Swift.h"
#import "XRSymbolEntry.h"
#import "objc_.h"
#import "XRMachOLibrary+ObjectiveC.h"
#import "XRMachOLibraryCplusHelpers.h"
#import "XRMachOLibrary+Disassemble.h"
#import "XRMachOLibraryCplusHelpers.h"

#import "XRMachOLibrary+ObjectiveC.h"
#import "XRMachOLibrary+SymbolDumper.h"
#import "objc_.h"

#endif /* Methods_hpp */

/// iOS 14 adds a __TEXT.__objc_methlist for int32_t offsets to methods, doesn't apply to protocols
void dumpObjectiveCMethods(method_list_t* methodList, const char *name, bool isMeta, bool isProtocol = false, const char * overrideColor = NULL);

const char* translate_method_type_to_string(char *typeString);
