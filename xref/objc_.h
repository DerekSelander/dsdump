//
//  objc_.h
//  xref
//
//  Created by Derek Selander on 5/13/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#ifndef objc__h
#define objc__h

#define FAST_DATA_MASK          0x00007ffffffffff8UL
#define ARM64e_MASK             0x000007FFFFFFFFFFUL
#define RO_META               (1<<0)

typedef struct {
    char* name;
    const char *types;
    void* imp;
} method_t;

typedef struct {
    uint32_t entsizeAndFlags;
    uint32_t count;
    method_t *methods;
} method_list_t;

typedef struct {
    uintptr_t isa_cls;
    uintptr_t superclass;
    void *_buckets;
    uint32_t _mask;
    uintptr_t _occupied;
    uintptr_t bits; // class_rw_t * after a &= FAST_DATA_MASK
} objc_class;

typedef struct {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
#ifdef __LP64__
    uint32_t reserved;
#endif
    
    const uint8_t * ivarLayout;
    
    const char * name;
    method_list_t * baseMethodList;
    void * baseProtocols; // protocol_list_t
    const void * ivars; // ivar_list_t
    
    const uint8_t * weakIvarLayout;
    void *baseProperties; // protocol_list_t
    
    
} class_ro_t;

typedef struct {
    uint32_t flags;
    uint32_t version;
    
    const class_ro_t* ro; // class_ro_t*
    
    void* methods; // method_array_t
    void* properties; // property_array_t
    void* protocols; // protocol_array_t
    
    void* firstSubclass; // Class
    void* nextSiblingClass; // Class
    
    char *demangledName;
    
} class_rw_t;





//#define OBJCClassGetRW(cls)  ((cls)->bits & FAST_DATA_MASK)


#endif /* objc__h */
