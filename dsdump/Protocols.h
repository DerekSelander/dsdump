//
//  Protocols.hpp
//  dsdump
//
//  Created by Derek Selander on 4/29/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#ifndef Protocols_hpp
#define Protocols_hpp

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
#import "Methods.h"
#import "Properties.h"

#endif /* Protocols_hpp */

void dumpObjectiveCProtocols(void);
BOOL listProtocolsForObjectiveCClass(swift_class* cls);
