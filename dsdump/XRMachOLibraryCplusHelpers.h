//
//  XRMachOLibraryCplusHelpers.h
//  dsdump
//
//  Created by Derek Selander on 6/4/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#ifndef XRMachOLibraryCplusHelpers_h
#define XRMachOLibraryCplusHelpers_h

#import "XRMachOLibrary.h"


 namespace dshelpers {
    
     template <typename T>
     T LoadFromDiskDeref(XRMachOLibrary *library, T* t) {
         uintptr_t loadAddress = reinterpret_cast<uintptr_t>(t);
         uintptr_t fileOff = [library translateLoadAddressToFileOffset:loadAddress useFatOffset:YES];
         T retT = *reinterpret_cast<T*>(&library.data[fileOff]);
         return retT;
     }
     
     template <typename T>
     T LoadFromDisk(XRMachOLibrary *library, T t) {
         uintptr_t loadAddress = *reinterpret_cast<uintptr_t*>(&t); // TODO find a better way than this...
         uintptr_t fileOff = [library translateLoadAddressToFileOffset:loadAddress useFatOffset:YES];
         T retT = reinterpret_cast<T>(&library.data[fileOff]);
         return retT;
     }
     
//     template <typename T
//     T LoadFromDisk(XRMachOLibrary *library, T t){
//         uintptr_t loadAddress = reinterpret_cast<uintptr_t>(t);
//
//         uintptr_t fileOff = [library translateLoadAddressToFileOffset:loadAddress useFatOffset:YES];
//         T retT = reinterpret_cast<T>(&library.data[fileOff]);
//         return retT;
//     }
    
//    ValueTy diskOff(uint8_t *data) {
//        DAT
}

#define FROMDISK_PTR(addr) dshelpers::LoadFromDisk(self, addr)

#define FROMDISK(addr) dshelpers::LoadFromDiskDeref(self, addr)

#endif /* XRMachOLibraryCplusHelpers_h */
