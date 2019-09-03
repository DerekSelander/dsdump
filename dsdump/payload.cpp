//
//  payload.cpp
//  dsdump
//
//  Created by Derek Selander on 6/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#include "payload.hpp"


// Likely from LLVM cmake
namespace llvm {
    int DisableABIBreakingChecks = 0;
};

// Holds the executable data
namespace payload {
    uint8_t *data;
    uintptr_t size; 
    std::vector<struct section_64 *> sections;
    uintptr_t offset;
    std::map<std::string, struct section_64 *> sectionsDict;
    
    uintptr_t Offset2Virtual(uintptr_t f) {
        auto r = ARM64E_POINTER(f);
        for (auto &sec : payload::sections) {
            if (sec->offset <= (r) && (r) < (sec->offset + sec->size)) {
                return r + sec->addr - sec->offset;
            }
        }
        
        printf( "WARNING: couldn't find offset 0x%lx in binary!\n", r);
        return 0;
    }
    
    uintptr_t Virtual2Offset(uintptr_t f) {
        auto r = ARM64E_POINTER(f);
        for (auto i = 0; i < payload::sections.size(); i++) {
            struct section_64 *sec  = payload::sections[i];
            if (sec->offset <= (r) && (r) < (sec->offset + sec->size)) {
                return r + sec->addr - sec->offset;
            }
        }
        
        printf( "WARNING: couldn't find offset 0x%lx in binary!\n", r);
        return 0;
    }
    


}

