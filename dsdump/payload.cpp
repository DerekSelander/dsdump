//
//  payload.cpp
//  dsdump
//
//  Created by Derek Selander on 6/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#include "payload.hpp"


// Holds the executable data
namespace payload {
    uint8_t *data;
    uintptr_t size; 
    std::vector<struct section_64 *> sections;
    uintptr_t offset;
    
    
}

