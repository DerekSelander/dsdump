//
//  Properties.hpp
//  dsdump
//
//  Created by Derek Selander on 4/28/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#ifndef Properties_hpp
#define Properties_hpp

#include <stdio.h>
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


void dumpObjCPropertiesWithResolvedAddress(protocol_t* prtl);
void dumpObjCPropertiesWithResolvedAddress(swift_class* cls);
void dumpObjCPropertiesWithResolvedAddress(property_list_t* propertiesList) ;

#endif /* Properties_hpp */
