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
        auto name = protocolDisk->mangledName->disk();
        printf("%s@protocol %s%s", dcolor(DSCOLOR_GREEN), name, color_end());
        if(!printObjectiveCProtocolsFromProtocol(protocolDisk)) {
            putchar('\n');
        }
        
        auto properties = protocol->instanceProperties;
        dumpObjCPropertiesWithResolvedAddress(properties);
        
        auto classMethods = protocol->classMethods;
        dumpObjectiveCMethods(classMethods, name, true, true);
        
        auto instanceMethods = protocol->instanceMethods;
        dumpObjectiveCMethods(instanceMethods, name, false, true);
        
        auto optionalInstanceMethods = protocol->optionalInstanceMethods;
        auto optionalClassMethods = protocol->optionalClassMethods;
        if (optionalClassMethods || optionalInstanceMethods) {
            printf("@optional\n");
        }
        
        dumpObjectiveCMethods(optionalClassMethods, name, true, true);
        dumpObjectiveCMethods(optionalInstanceMethods, name, false, true);
        
        
  
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

