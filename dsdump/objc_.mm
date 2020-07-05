//
//  objc_.cpp
//  dsdump
//
//  Created by Derek Selander on 7/4/20.
//  Copyright © 2020 Selander. All rights reserved.
//
#import <Foundation/Foundation.h>
#import "objc_.h"

static bool useRelativeMethUsage(void) {
    static dispatch_once_t onceToken;
    static bool useRelativeMeth = false;
    dispatch_once(&onceToken, ^{
        auto section = payload::sectionsDict["__TEXT.__objc_methlist"];
        if (section) {
            useRelativeMeth = true;
        }
    });
    return useRelativeMeth;
}

payload::LoadToDiskTranslator<const char>* method_t::getName() {

    if (useRelativeMethUsage()) {
          auto typeOffsets = payload::DiskWrapper<int32_t>::Cast(this->disk());
        auto resolvedAddress = ((intptr_t)typeOffsets[0].disk() + *typeOffsets[0].disk());
        
        auto cur = payload::CastToDisk<method_t>(resolvedAddress);
        return cur->disk()->name;
    }
    return this->name;
}
payload::LoadToDiskTranslator<const char>* method_t::getTypes() {
    if (useRelativeMethUsage()) {
          auto typeOffsets = payload::DiskWrapper<int32_t>::Cast(this->disk());
        auto resolvedAddress = ((intptr_t)typeOffsets[1].disk() + *typeOffsets[1].disk());
        auto cur = payload::CastToDisk<const char>(resolvedAddress);
        return cur;
    }
    return this->types;
}
payload::LoadToDiskTranslator<uintptr_t, true>* method_t::getImp() {
    if (useRelativeMethUsage()) {
        auto typeOffsets = payload::DiskWrapper<int32_t>::Cast(this->disk());
        
        auto resolvedAddress = ((intptr_t)typeOffsets[2].disk() + *typeOffsets[2].disk());
        
        auto impPointer = reinterpret_cast<payload::LoadToDiskTranslator<uintptr_t, true>*>(resolvedAddress);
        return impPointer;
    }
    return this->imp;
}

method_t*  method_list::GetMethod(int i, bool isProtocol) {
    auto startAddress = &this->first_method;
    if (!isProtocol && useRelativeMethUsage()) {
        
        // TODO This is for 64 bit only, probably would never get to 32 bit... : ]
        auto addr = reinterpret_cast<uintptr_t>(startAddress) + (i * (sizeof(int32_t) * 3));
        return reinterpret_cast<method_t *>(addr);
    }
    return &startAddress[i];
}
