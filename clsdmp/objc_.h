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
#define RO_ROOT               (1<<1)

/*****************************************************************
 methods
 *****************************************************************/

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

/*****************************************************************
 ivars
 *****************************************************************/

typedef struct {
    int32_t *offset;
    const char *name;
    const char *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
} ivar_t;

typedef struct {
    uint32_t entsizeAndFlags;
    uint32_t count;
    ivar_t *ivars;
} ivar_list_t;

/*****************************************************************
 properties
 *****************************************************************/

typedef struct  {
    const char *name;
    const char *attributes;
} property_t;

typedef struct {
    uint32_t entsizeAndFlags;
    uint32_t count;
    property_t *properties;
} property_list_t;

/*****************************************************************
 class stuff, ro/rw
 *****************************************************************/

typedef struct {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    
    const uint8_t * ivarLayout;
    
    const char * name;
    method_list_t * baseMethodList;
    void * baseProtocols; // protocol_list_t
    const ivar_list_t * ivars; // ivar_list_t
    
    const uint8_t * weakIvarLayout;
    void *baseProperties; // property_list_t
    
} class_ro_t; // The structure when on disk or before first call

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
    
} class_rw_t; // The structure when loaded into memory


/*
 class TargetClassDescriptor final
 : public TargetTypeContextDescriptor<Runtime>,
 public TrailingGenericContextObjects<TargetClassDescriptor<Runtime>,
 TargetTypeGenericContextDescriptorHeader,
 // additional trailing objects:
 TargetResilientSuperclass<Runtime>,
 TargetForeignMetadataInitialization<Runtime>,
 TargetSingletonMetadataInitialization<Runtime>,
 TargetVTableDescriptorHeader<Runtime>,
 TargetMethodDescriptor<Runtime>,
 TargetOverrideTableHeader<Runtime>,
 TargetMethodOverrideDescriptor<Runtime>,
 TargetObjCResilientClassStubInfo<Runtime>> {
 private:
 using TrailingGenericContextObjects =
 TrailingGenericContextObjects<TargetClassDescriptor<Runtime>,
 TargetTypeGenericContextDescriptorHeader,
 TargetResilientSuperclass<Runtime>,
 TargetForeignMetadataInitialization<Runtime>,
 TargetSingletonMetadataInitialization<Runtime>,
 TargetVTableDescriptorHeader<Runtime>,
 TargetMethodDescriptor<Runtime>,
 TargetOverrideTableHeader<Runtime>,
 TargetMethodOverrideDescriptor<Runtime>,
 TargetObjCResilientClassStubInfo<Runtime>>;
 */

typedef struct __attribute__ ((packed))  swift_descriptor {
    // class TargetTypeContextDescriptor, struct TargetContextDescriptor,
    uint32_t flags; // ContextDescriptorFlags Flags;
    void *parent; // RelativeContextPointer<Runtime> Parent;
} swift_descriptor;



// ObjC class heeeeeeeeeeeeeeeereeeeeeeee
typedef struct {
    uintptr_t isa_cls;
    uintptr_t superclass;
    void *_buckets;
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits; //(class_ro_t* before access (and on disk), class_rw_t * after access) &= FAST_DATA_MASK
} objc_class;

// Swift class heeeeeeeeeeeeeeeereeeeeeeee
typedef struct swift_class_t {
    uintptr_t isa_cls;
    uintptr_t superclass;
    void *_buckets;
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits; //(class_ro_t* before access (and on disk), class_rw_t * after access) &= FAST_DATA_MASK
    uint32_t flags;
    uint32_t instanceAddressOffset;
    uint32_t instanceSize;
    uint16_t instanceAlignMask;
    uint16_t reserved;
    
    uint32_t classSize;
    uint32_t classAddressOffset;
    swift_descriptor *description;
    void *ivar_destroyer;
    uintptr_t *swiftMethods;
    // ...
    
} swift_class;

#endif /* objc__h */
