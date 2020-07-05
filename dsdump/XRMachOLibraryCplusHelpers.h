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
#import "payload.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

//#define protected public
//#define private public
//#define class struct

#import "swift/Demangling/Demangler.h"

//#undef protected
//#undef private
//#undef class


#pragma clang diagnostic pop


 namespace dshelpers {
     extern swift::Demangle::DemangleOptions simplifiedOptions;
     extern Context context;
     
     const char *simple_demangle(const char *mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options = dshelpers::simplifiedOptions);
     bool canDemangle(StringRef mangled);
     const char *simple_demangle(char *mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options = dshelpers::simplifiedOptions);
     const char *simple_demangle(StringRef mangled, std::string &strout_ref, swift::Demangle::DemangleOptions options = dshelpers::simplifiedOptions);

//   Compact mode: display module names or implicit self types in addition to demangled names
     const char *compact_demangle(char *mangled, std::string &strout_ref);
     
//     const char *simple_type(StringRef type);
     const char *simple_type(StringRef type, std::string &strout_ref);
     const char *simple_type(char* type, std::string &strout_ref);
     const char *simple_type(const char* type, std::string &strout_ref);
     
     
     template <typename T>
     T LoadToOffsetDeref(XRMachOLibrary *library, T* t) {
         uintptr_t loadAddress = reinterpret_cast<uintptr_t>(t);
         uintptr_t fileOff = [library translateLoadAddressToFileOffset:loadAddress useFatOffset:YES];
         T retT = *reinterpret_cast<T*>(&payload::data[fileOff]);
         return retT;
     }
     
     template <typename T>
     T LoadToOffset(XRMachOLibrary *library, T t) {
         uintptr_t loadAddress = *reinterpret_cast<uintptr_t*>(&t); // TODO find a better way than this...
         uintptr_t fileOff = [library translateLoadAddressToFileOffset:(loadAddress) useFatOffset:YES];
         T retT = reinterpret_cast<T>(&payload::data[fileOff]);
         return retT;
     }
     
     template <typename T>
     T OffsetToLoad(XRMachOLibrary *library, T t) {
         uintptr_t offset = *reinterpret_cast<uintptr_t*>(&t);
         uintptr_t loadAddress = [library translateOffsetToLoadAddress:offset - (uintptr_t)&payload::data[0]];
         T retT = *reinterpret_cast<T*>(&loadAddress);
         return retT;
     }
     
     
     
     
//     template <typename T
//     T LoadTODISKDEREF(XRMachOLibrary *library, T t){
//         uintptr_t loadAddress = reinterpret_cast<uintptr_t>(t);
//
//         uintptr_t fileOff = [library translateLoadAddressToFileOffset:loadAddress useFatOffset:YES];
//         T retT = reinterpret_cast<T>(&library.data[fileOff]);
//         return retT;
//     }
    
//    ValueTy diskOff(uint8_t *data) {
//        DAT
}



#define TODISK(addr) dshelpers::LoadToOffset(self, addr)

#define TODISKDEREF(addr) dshelpers::LoadToOffsetDeref(self, addr)

#define FROMDISK(addr) dshelpers::OffsetToLoad(self, addr)

//#define FROM(addr) dshelpers::LoadToOffsetDeref(self, addr)

#endif /* XRMachOLibraryCplusHelpers_h */
