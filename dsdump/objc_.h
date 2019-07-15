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


#import "payload.hpp"
#pragma clang diagnostic ignored "-Weverything"

#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"

#import  <typeinfo>
#pragma clang diagnostic pop

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

typedef struct class_ro  {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    
    const uint8_t * ivarLayout;
    
//    const char * name;
    payload::LoadToDiskTranslator<char>* name;
    method_list_t * baseMethodList;
    void * baseProtocols; // protocol_list_t
    const ivar_list_t * ivars; // ivar_list_t
    
    const uint8_t * weakIvarLayout;
    void *baseProperties; // property_list_t
    
//    char * disk_name() {
//        return this->name->disk()->unwrap();
//    }
    
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

/*
 
 
 
 */


typedef enum __attribute__((packed)) {
    DescriptorKindModule = 0,
    DescriptorKindExtension = 1,
    DescriptorKindAnonymous = 2,
    DescriptorKindProtocol = 3,
    DescriptorKindOpaque = 4,
    DescriptorKindClass = 16,
    DescriptorKindStruct = 17,
    DescriptorKindEnum = 18
} DescriptorKind;


typedef struct {
    DescriptorKind kind: 8;
    int32_t remainder: 24;
} DescriptorFlags;


/// Kinds of context descriptor.
//// struct ContextDescriptorKind : uint8_t {
//    /// This context descriptor represents a module.
//    Module = 0,
//
//    /// This context descriptor represents an extension.
//    Extension = 1,
//
//    /// This context descriptor represents an anonymous possibly-generic context
//    /// such as a function body.
//    Anonymous = 2,
//
//    /// This context descriptor represents a protocol context.
//    Protocol = 3,
//
//    /// This context descriptor represents an opaque type alias.
//    OpaqueType = 4,
//
//    /// First kind that represents a type of any sort.
//    Type_First = 16,
//
//    /// This context descriptor represents a class.
//    Class = Type_First,
//
//    /// This context descriptor represents a struct.
//    Struct = Type_First + 1,
//
//    /// This context descriptor represents an enum.
//    Enum = Type_First + 2,
//
//    /// Last kind that represents a type of any sort.
//    Type_Last = 31,
//};

#define DescriptorFlagsGetKind(flags) ((flags) & 0xFu)
#define DescriptorFlagsGetIsGeneric(flags) ((flags) & 0x80u)
#define DescriptorFlagsGetIsUnique(flags) ((flags) & 0x40u)
#define DescriptorFlagsGetVersion(flags) (((flags) >> 8u) 0xFFu)
#define DescriptorFlagsGetKindSpecificFlags(flags) (((flags) >> 16u) & 0xFFFFu)


// TargetClassDescriptor found in Metadata.h
typedef struct   {
    // class TargetTypeContextDescriptor, struct TargetContextDescriptor,
    DescriptorFlags flags; // struct TargetContextDescriptor, see ContextDescriptorFlags
    int32_t parentOffset; // struct TargetContextDescriptor
    int32_t namedOffset; // class TargetTypeContextDescriptor
    
    /// A pointer to the metadata accessor function for this type, only really useful in process
    int32_t accessFunctionOffset; // TargetTypeContextDescriptor
    
    /// A pointer to the field descriptor for the type, if any.
    int32_t fieldsOffset; // TargetTypeContextDescriptor

    
    
    /// The type of the superclass, expressed as a mangled type name that can
    /// refer to the generic arguments of the subclass type.
    int32_t superclassTypeOffset;
    
//    union {
        /// If this descriptor does not have a resilient superclass, this is the
        /// negative size of metadata objects of this class (in words).
//        uint32_t MetadataNegativeSizeInWords;
        
        /// If this descriptor has a resilient superclass, this is a reference
        /// to a cache holding the metadata's extents.
        int32_t ResilientMetadataBounds;
//    };
    
//    union {
        /// If this descriptor does not have a resilient superclass, this is the
        /// positive size of metadata objects of this class (in words).
//        uint32_t MetadataPositiveSizeInWords;
        
        /// Otherwise, these flags are used to do things like indicating
        /// the presence of an Objective-C resilient class stub.
        uint32_t ExtraClassFlags;
//    };
    
    /// The number of additional members added by this class to the class
    /// metadata.  This data is opaque by default to the runtime, other than
    /// as exposed in other members; it's really just
    /// NumImmediateMembers * sizeof(void*) bytes of data.
    ///
    /// Whether those bytes are added before or after the address point
    /// depends on areImmediateMembersNegative().
    uint32_t NumImmediateMembers; // ABI: could be uint16_t?

    
//    int32_t reflectionOffset;
//    int32_t parentTyperefOffset;
////    uint32_t fieldOffsetVector;
//    int32_t numFields;
//    int32_t fieldsOffset;
//
//        /// The number of additional members added by this class to the class
//        /// metadata.  This data is opaque by default to the runtime, other than
//        /// as exposed in other members; it's really just
//        /// NumImmediateMembers * sizeof(void*) bytes of data.
//        ///
//        /// Whether those bytes are added before or after the address point
//        /// depends on areImmediateMembersNegative().
//        uint32_t NumImmediateMembers; // ABI: could be uint16_t?
//        
//
//        
//        /// The number of stored properties in the class, not including its
//        /// superclasses. If there is a field offset vector, this is its length.
//        uint32_t NumFields;
//        
////    private:
//        /// The offset of the field offset vector for this class's stored
//        /// properties in its metadata, in words. 0 means there is no field offset
//        /// vector.
//        ///
//        /// If this class has a resilient superclass, this offset is relative to
//        /// the size of the resilient superclass metadata. Otherwise, it is
//        /// absolute.
//        uint32_t FieldOffsetVectorOffset;
//    
//    
    
} swift_descriptor;

#define ResolveSwiftDescriptorAddress(addr, name) *(uint32_t *)(DATABUF((uintptr_t)[self translateLoadAddressToFileOffset:(uintptr_t)addr useFatOffset:YES] + offsetof(swift_descriptor, name)))


#define TEST(addr, name)  ((uintptr_t)addr + offsetof(swift_descriptor, name) + addr->name)


// ObjC class heeeeeeeeeeeeeeeereeeeeeeee
typedef struct ds_objc_class {
    payload::VirtualDiskPointer<struct ds_objc_class> isa_cls;
    payload::VirtualDiskPointer<struct ds_objc_class> superclass;
    void *_buckets;
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits; //(class_ro_t* before access (and on disk), class_rw_t * after access) &= FAST_DATA_MASK
} ds_objc_class_t;

// class ModuleDecl : public DeclContext, public TypeDecl {
typedef struct {
    unsigned DeclContextKind; // various types, from DeclContext
    
    
} ModuleDecl;




//typedef  class FieldDescriptorKind : uint16_t {
//    // Swift nominal types.
//    Struct,
//    Class,
//    Enum,
//
//    // Fixed-size multi-payload enums have a special descriptor format that
//    // encodes spare bits.
//    //
//    // FIXME: Actually implement this. For now, a descriptor with this kind
//    // just means we also have a builtin descriptor from which we get the
//    // size and alignment.
//    MultiPayloadEnum,
//
//    // A Swift opaque protocol. There are no fields, just a record for the
//    // type itself.
//    Protocol,
//
//    // A Swift class-bound protocol.
//    ClassProtocol,
//
//    // An Objective-C protocol, which may be imported or defined in Swift.
//    ObjCProtocol,
//
//    // An Objective-C class, which may be imported or defined in Swift.
//    // In the former case, field type metadata is not emitted, and
//    // must be obtained from the Objective-C runtime.
//    ObjCClass
//};
//

template<typename T>
struct PtrCheck : public T {
    static const bool isPtr(){ return false; }
    
};

template<typename T>
struct PtrCheck<T*> : public T {
    static const bool isPtr(){ return true; }
    
};

template<typename T>
void func(const std::vector<T>& v) {
//    std::cout << "is it a pointer? " << is_pointer<T>::value << std::endl;
}

typedef struct {

    int32_t mangledTypeName;
    int32_t superclass;
    int16_t kind;
//    FieldDescriptorKind kind;
    uint16_t FieldRecordSize;
    uint32_t NumFields;

} FieldDescriptor;

// Swift class heeeeeeeeeeeeeeeereeeeeeeee
typedef struct swift_class_t  : public payload::LoadToDiskTranslator<struct swift_class_t >  {
    using SwiftClassDescriptor = payload::LoadToDiskTranslator<swift::TargetClassDescriptor<swift::InProcess>>;
    
    
    
    struct swift_class_t *isa_cls;
    struct swift_class_t *superclass;
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
    SwiftClassDescriptor *descriptor;
    void *ivar_destroyer;
    uintptr_t *swiftMethods;
    

    inline payload::LoadToDiskTranslator<class_ro_t> *rodata() {
        auto resolved = bits & FAST_DATA_MASK;
        auto rodata = reinterpret_cast<payload::LoadToDiskTranslator<class_ro_t>*>(resolved);
        return rodata;
    }
    

    
    
//    inline swift_class_t* operator ->() {
////        auto aa = typeid(this).name();
//        
////        if (std::is_pointer<typeid(this)>) {
////            printf("yay");
////        } else {
////            printf("woo");
////        }
//        return this;
//    }
    
    
//    inline swift_class_t *disk_superclass() {
//        return this->superclass->disk()->unwrap();
//    }
//    
//    inline class_ro_t *disk_rodata() {
////        if (!this->rodata)
//        return this->rodata()->disk()->unwrap();
//    }
    

} swift_class;



//
//template <typename U, typename T>
//struct  swift_class_t : payload::AddressTranslatorWrapper<T*> {
//    swift_class_t * operator->() {
//        return this;
//    }
//}




#endif /* objc__h */
