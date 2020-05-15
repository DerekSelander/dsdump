//
//  Protocols.cpp
//  dsdump
//
//  Created by Derek Selander on 4/29/20.
//  Copyright © 2020 Selander. All rights reserved.
//

#include "Protocols.h"


static BOOL printObjectiveCProtocolsFromProtocol(protocol_t* protocol);
/********************************************************************************
// Protocols
********************************************************************************/

void dumpObjectiveCProtocols(void) {
    if (xref_options.undefined) {
        return;
    }
    struct section_64* protocolsSection = payload::sectionsDict["__DATA.__objc_protolist"];
    if (!protocolsSection) {
        protocolsSection = payload::sectionsDict["__DATA_CONST.__objc_protolist"];
    }
    if (!protocolsSection) {
        return;
    }
    
    auto protocolsDisk = payload::LoadToDiskTranslator<uintptr_t*>::Cast(protocolsSection->addr)->disk();
    for (int i = 0; i < protocolsSection->size / PTR_SIZE; i++) {
        auto protocol = payload::Cast<protocol_t*>(protocolsDisk[i]);
        if (protocol == nullptr) {
            continue;
        }
        auto protocolDisk = protocol->disk();
        auto name = protocolDisk->mangledName ? protocolDisk->mangledName->disk() : "BUG DEREK";
        if (!ContainsFilteredWords(name)) {
            continue;
        }
        printf("%s@protocol %s%s%s%s", dcolor(DSCOLOR_YELLOW), color_end(), dcolor(DSCOLOR_MAGENTA), name, color_end());
        if(!printObjectiveCProtocolsFromProtocol(protocolDisk)) {
            putchar('\n');
        }
        
        if (protocolDisk->instanceProperties) {
            auto properties = protocolDisk->instanceProperties->disk();
            dumpObjCPropertiesWithResolvedAddress(properties);
        }
        
        if (protocolDisk->classMethods) {
            auto classMethods = protocolDisk->classMethods->disk();
            dumpObjectiveCMethods(classMethods, name, true, true, dcolor(DSCOLOR_YELLOW));
        }
        
        if (protocolDisk->instanceMethods) {
            auto instanceMethods = protocolDisk->instanceMethods->disk();
            dumpObjectiveCMethods(instanceMethods, name, false, true, dcolor(DSCOLOR_YELLOW));
        }
            
        auto optionalInstanceMethods = protocolDisk->optionalInstanceMethods;
        auto optionalClassMethods = protocolDisk->optionalClassMethods;
        if (optionalClassMethods || optionalInstanceMethods) {
            printf("%s@optional%s\n", dcolor(DSCOLOR_YELLOW), color_end());
        }
        
        dumpObjectiveCMethods(optionalClassMethods, name, true, true, dcolor(DSCOLOR_YELLOW));
        dumpObjectiveCMethods(optionalInstanceMethods, name, false, true, dcolor(DSCOLOR_YELLOW));
        
        printf("%s@end%s\n\n", dcolor(DSCOLOR_YELLOW), color_end());
    }
}


static BOOL printObjectiveCProtocolsFromProtocol(protocol_t* protocol) {
    if (xref_options.verbose <= VERBOSE_1) {
        return NO;
    }
    
    if (!protocol->disk()->protocols)  {
        return NO;
    }
    auto protocolList = protocol->disk()->protocols->disk();
    auto count = protocolList->disk()->count;
    if (count == 0) {
        return NO;
    }

    auto protocols = &protocolList->disk()->first_protocol;
    printf("%s <", dcolor(DSCOLOR_YELLOW));

    for (int i = 0; i < count; i++) {
        auto prot = protocols[i];
        auto mangledName = prot->disk()->mangledName->disk();
        printf("%s", mangledName ? mangledName : "<unknown>");
        if (i != count - 1) {
            putchar(',');
            putchar(' ');
        }
    }
    printf(">\n%s", color_end());

    return YES;
}

BOOL listProtocolsForObjectiveCClass(protocol_list_t* protocolList)  {
    if (protocolList == nullptr) {
        return NO;
    }
    
    auto count = protocolList->disk()->count;
    if (count == 0) {
        return NO;
    }
    
    auto protocols = &protocolList->disk()->first_protocol;
    printf("%s <", dcolor(DSCOLOR_YELLOW));
    
    for (int i = 0; i < count; i++) {
        auto prot = protocols[i];
        auto mangledName = prot->disk()->mangledName->disk();
        printf("%s", mangledName ? mangledName : "<unknown>");
        if (i != count - 1) {
            putchar(',');
            putchar(' ');
        }
    }
    printf(">\n%s", color_end());
    return YES;
}

BOOL listProtocolsForObjectiveCClass(swift_class* cls) {
    if (xref_options.verbose <= VERBOSE_1) {
        return NO;
    }
    
    auto rodata = cls->disk()->rodata();
    if (rodata == nullptr) {
        return NO;
    }
    
    auto protocolList = rodata->disk()->baseProtocols;
    return listProtocolsForObjectiveCClass(protocolList);
}

