//
//  payload.hpp
//  dsdump
//
//  Created by Derek Selander on 6/10/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#ifndef payload_hpp
#define payload_hpp

#import <type_traits>
#import <stdio.h>
#import <vector>
#import <mach-o/loader.h>

namespace payload {
    
    extern uint8_t *data;
    extern uintptr_t size;
    extern std::vector<struct section_64 *> sections;
    extern uintptr_t offset;
    
    
    
    uintptr_t Offset2Virtual(uintptr_t f);

    /*
     I started writing this having to deal with translating the load address to the file offset on disk.
     It was particularly painful getting a pointer on disk, having to recast it to the proper load address
     then keep on going. This AddressTranslator class aims to clean up all that shitty code that I initially wrote
     */
    template <typename ValueT>
    struct VirtualDiskPointer  {
        ValueT *val;
    public:
        //        inline payload::VirtualDiskPointer<ValueT> *disk() {
        //            if (isDisk()) { return this; }
        //            auto loadAddress = reinterpret_cast<uintptr_t>(&this->val) + payload::offset;
        //            for (auto &sec : sections) {
        //                if (sec->addr <= loadAddress && loadAddress < sec->addr + sec->size) {
        //                    uintptr_t resolvedOffset = loadAddress - sec->addr  + sec->offset;
        //                    uint8_t *resolvedAddress = &payload::data[resolvedOffset];
        //                    auto payload = reinterpret_cast<payload::VirtualDiskPointer<ValueT>*>(resolvedAddress);
        //                    return payload;
        //                }
        //            }
        //
        //            ::printf("WARNING: couldn't find address %p in binary!\n", (void*)&this->val);
        //            return this;
        //        }
        //
        //        inline payload::VirtualDiskPointer<ValueT> *load() {
        //            if (isLoad()) { return this; }
        //            auto offset = reinterpret_cast<uintptr_t>(&this->val) - reinterpret_cast<uintptr_t>(payload::data) + payload::offset;
        //            for (auto &sec : sections) {
        //                if (sec->offset <= (offset) && (offset) < (sec->offset + sec->size)) {
        //                    auto resolvedLoad = offset - sec->offset + sec->addr;
        //                    auto payload = reinterpret_cast<payload::VirtualDiskPointer<ValueT> *>(resolvedLoad);
        //                    return payload;
        //                }
        //
        //            }
        //            ::printf("WARNING: couldn't find address %p in binary!\n", (void*)&this->val);
        //            return this;
        //        }
        //
        //        inline bool isNull() {
        //            return val == nullptr;
        //        }
        //
        //        inline bool isLoad() {
        //            return !isDisk();
        //        }
        //
        //
        //        inline ValueT* unwrap() {
        //            return reinterpret_cast<ValueT *>(&this->val);
        //        }
        //
        //         payload::VirtualDiskPointer<ValueT>* operator->() {
        //            printf("-> op\n");
        //            //            return &val;
        ////            return reinterpret_cast<payload::AddressTranslator<ValueT> *>(&val->diskGet());
        //             return this;
        //        }
        //
        
        
        
        
    };
    
    
    ////    template <typename ValueT>
    //    class PointerOffsetType  {
    ////    private:
    ////        int32_t offset;
    ////    public:
    ////        inline ValueT get() {
    ////            auto resolved = reinterpret_cast<uintptr_t>(this) + offset;
    ////            return reinterpret_cast<ValueT>(resolved);
    ////        }
    //    };
    
    //    template <typename T>
    //    struct AddressTranslatorWrapper  {
    //        payload::AddressTranslatorWrapper<T> * operator->() {
    //            printf("hay");
    //            return nullptr;
    //        }
    //
    //    };
    //
    //    template <typename T>
    //    class AddressTranslatorWrapper <T *> {
    //        payload::AddressTranslatorWrapper<T*> * operator->() {
    //            printf("yay");
    //            return nullptr;
    //        }
    //    };
    //
    
//#define PAC_this  ((uintptr_t)this & 0x000007FFFFFFFFFFUL)
    
    
    template <class T>
    struct LoadToDiskTranslator {
        
        /// This assumes the disk address (the address mmap'd in memory) doesn't overlap with the virtual address
        /// Right now it's set to a weird address Apple infrequently (never?) uses... 0x4000..something
        inline bool isDisk() {
            auto d = reinterpret_cast<uintptr_t>(payload::data);
            auto v = reinterpret_cast<uintptr_t>(this);
            return v >= d && v <= (d + payload::size);
        }
        
        inline uintptr_t strip_PAC() {
            auto p = reinterpret_cast<uintptr_t>(this);
//            auto r = ((p & (1UL << 63)) ?
//                    (((uintptr_t)p & 0x0000000ffffffffUL) | 0x000100000000UL)
//                    :   ((uintptr_t)p & 0x0000000fffffffffUL));
            auto r = payload::Offset2Virtual(p);
//            printf("\n%p  -> %p\n", (void*)p, (void*)r);
            return r;
        }
        
        inline bool isLoad() {
            return !isDisk();
        }
        
        inline T* load() {
            if (isLoad()) {return reinterpret_cast<T*>((uintptr_t)strip_PAC());  }
            auto offset = reinterpret_cast<uintptr_t>(strip_PAC()) - reinterpret_cast<uintptr_t>(payload::data) + payload::offset;
            for (auto &sec : payload::sections) {
                if (sec->offset <= (offset) && (offset) < (sec->offset + sec->size)) {
                    auto resolvedLoad = offset - sec->offset + sec->addr;
                    auto payload = reinterpret_cast<T*>(resolvedLoad);
                    return payload;
                }
            }
            ::printf("WARNING: couldn't find address %p in binary!\n", (void*)this);
            return nullptr;
        }
        
        inline T* disk() {
            if (isDisk()) { return reinterpret_cast<T*>((uintptr_t)this); }
            
            auto loadAddress = reinterpret_cast<uintptr_t>(strip_PAC()) + payload::offset;
            for (auto &sec : payload::sections) {
                if (sec->addr <= loadAddress && loadAddress < sec->addr + sec->size) {
                    uintptr_t resolvedOffset = loadAddress - sec->addr  + sec->offset;
                    uint8_t *resolvedAddress = &payload::data[resolvedOffset];
                    auto payload = reinterpret_cast<T*>((uintptr_t)resolvedAddress & 0x000007FFFFFFFFFFUL);
                    return payload;
                }
            }
            
            ::printf("WARNING: couldn't find address %p (%p) in binary!\n", (void*)this, (void*)loadAddress);
            return nullptr;
        }
        
        
        
        T* operator ->() {
            auto disk = this->disk();
            return  reinterpret_cast<T*>(disk);
        }
        

    };
    
    
    
    template <typename T>
    struct AddressTranslator : public T {
    private:
        //    bool _isLoad;
    public:
        AddressTranslator(T _t )   { }
        AddressTranslator<T>* operator->() {
            
            return this;
        }
        
        
        inline bool isDisk() {
            //        return !_isLoad;
            return false;
        }
        
        inline bool isLoad() {
            //        return _isLoad;
            return false;
        }
        
        AddressTranslator<T> disk() {
            if (isDisk()) { return this; }
            auto loadAddress = reinterpret_cast<uintptr_t>(this) + payload::offset;
            for (auto &sec : payload::sections) {
                if (sec->addr <= loadAddress && loadAddress < sec->addr + sec->size) {
                    uintptr_t resolvedOffset = loadAddress - sec->addr  + sec->offset;
                    uint8_t *resolvedAddress = &payload::data[resolvedOffset];
                    auto payload = reinterpret_cast<T*>(resolvedAddress);
                    return AddressTranslator(payload, false);
                }
            }
            ::printf("WARNING: couldn't find address %p in binary!\n", (void*)&this->val);
            return this;
        }
        
        AddressTranslator<T> *load() {
            if (isLoad()) { return this; }
            auto offset = reinterpret_cast<uintptr_t>(&this->val) - reinterpret_cast<uintptr_t>(payload::data) + payload::offset;
            for (auto &sec : payload::sections) {
                if (sec->offset <= (offset) && (offset) < (sec->offset + sec->size)) {
                    auto resolvedLoad = offset - sec->offset + sec->addr;
                    auto payload = reinterpret_cast<T*>(resolvedLoad);
                    return AddressTranslator(payload, true);
                }
                
            }
            ::printf("WARNING: couldn't find address %p in binary!\n", (void*)&this->val);
            return this;
        }
        
        //    inline bool isDisk() {
        //        auto d = reinterpret_cast<uintptr_t>(payload::data);
        //        auto v = reinterpret_cast<uintptr_t>(&this->val);
        //        return v >= d && v <= (d + payload::size);
        //    }
    };
    
    
    template <typename T>
    struct AddressTranslator <T*> : public T   {
        
        AddressTranslator(T *_t)     {  }
        //    AddressTranslator<T>* operator->() {
        //        return this;
        //    }
        
        
        //    inline bool isDisk() {
        //        auto d = reinterpret_cast<uintptr_t>(payload::data);
        //        auto v = reinterpret_cast<uintptr_t>(&this->val);
        //        return v >= d && v <= (d + payload::size);
        //    }
    };
    
}
#endif /* payload_hpp */
