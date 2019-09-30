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

#define RO_META               (1<<0)
#define RO_ROOT               (1<<1)

#import "payload.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#define protected public
#define private public
//#define class struct

#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"

#undef protected
#undef private
//#undef class


#pragma clang diagnostic pop

#import  <typeinfo>

/*****************************************************************
 protocols
 *****************************************************************/

typedef struct method_list method_list_t;
typedef struct property_list property_list_t;
typedef struct protocol_list protocol_list_t;

struct protocol_t : public payload::LoadToDiskTranslator<struct protocol_t >  {
    void *isa;
    payload::LoadToDiskTranslator<const char> *mangledName;
    protocol_list_t *protocols;
    method_list_t *instanceMethods;
    method_list_t *classMethods;
    method_list_t *optionalInstanceMethods;
    method_list_t *optionalClassMethods;
    property_list_t *instanceProperties;
    uint32_t size;   // sizeof(protocol_t)
    uint32_t flags;
    // Fields below this point are not always present on disk.
    const char **_extendedMethodTypes;
    const char *_demangledName;
    property_list_t *_classProperties;
};

typedef struct protocol_list : public payload::LoadToDiskTranslator<struct protocol_list>  {
    uintptr_t count;
    protocol_t *first_protocol; // variable-size
} protocol_list_t;

/*****************************************************************
 methods
 *****************************************************************/

typedef struct method : public payload::LoadToDiskTranslator<struct method> {
    payload::LoadToDiskTranslator<const char>* name;
    payload::LoadToDiskTranslator<const char> *types;
    // true for isCodePointer, different value for PAC
    payload::LoadToDiskTranslator<uintptr_t, true>* imp;
} method_t;

typedef struct method_list : public payload::LoadToDiskTranslator<struct method_list> {
    uint32_t entsizeAndFlags;
    uint32_t count;
    method_t first_method;
} method_list_t;

/*****************************************************************
 ivars
 *****************************************************************/

typedef struct ivar : public payload::LoadToDiskTranslator<struct ivar> {
    payload::LoadToDiskTranslator<int32_t> *offset;
    payload::LoadToDiskTranslator<const char> *name;
    payload::LoadToDiskTranslator<const char> *type;
    // alignment is sometimes -1; use alignment() instead
    uint32_t alignment_raw;
    uint32_t size;
} ivar_t;

typedef struct ivar_list : public payload::LoadToDiskTranslator<struct ivar_list> {
    uint32_t entsizeAndFlags;
    uint32_t count;
    payload::LoadToDiskTranslator<ivar_t> first_ivar;
} ivar_list_t;

/*****************************************************************
 properties
 *****************************************************************/

typedef struct property : public payload::LoadToDiskTranslator<struct property>  {
    payload::LoadToDiskTranslator<const char> *name;
    payload::LoadToDiskTranslator<const char> *attributes;
} property_t;

typedef struct property_list : public payload::LoadToDiskTranslator<struct property_list> {
    uint32_t entsizeAndFlags;
    uint32_t count;
    property_t first_property;
} property_list_t;

/*****************************************************************
 categories
 *****************************************************************/

typedef struct swift_class_t swift_class;

typedef struct category : public payload::LoadToDiskTranslator<struct category> {
    payload::LoadToDiskTranslator<const char>* name;
    swift_class *cls;
    method_list_t *instanceMethods;
    method_list_t *classMethods;
    protocol_list_t *protocols;
    property_list_t *instanceProperties;
    // Fields below this point are not always present on disk.
    property_list_t *_classProperties;
    
    method_list_t *methodsForMeta(bool isMeta) {
        if (isMeta) return classMethods;
        else return instanceMethods;
    }
    
    property_list_t *propertiesForMeta(bool isMeta, struct header_info *hi);
} category_t;


/*****************************************************************
 class stuff, ro/rw
 *****************************************************************/

typedef struct class_ro : public payload::LoadToDiskTranslator<struct class_ro>  {
    uint32_t flags;
    uint32_t instanceStart;
    uint32_t instanceSize;
    uint32_t reserved;
    
    const uint8_t * ivarLayout;
    

    payload::LoadToDiskTranslator<char>* name;
    method_list_t * baseMethodList;
    protocol_list_t * baseProtocols;
    ivar_list_t* ivarList;
    const uint8_t * weakIvarLayout;
    property_list_t *baseProperties;
    
} class_ro_t; // The structure when on disk or before "realized" in memory

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
    
} class_rw_t; // The structure when realize in memory




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


// Swift class heeeeeeeeeeeeeeeereeeeeeeee
typedef struct swift_class_t  : public payload::LoadToDiskTranslator<struct swift_class_t, true>  {
    using SwiftClassDescriptor = payload::LoadToDiskTranslator<swift::ClassDescriptor>;
    
    struct swift_class_t *isa_cls;
    struct swift_class_t *superclass;
    void *_buckets;
    uint32_t _mask;
    uint32_t _occupied;
    uintptr_t bits; // (class_ro_t* before access (and on disk), class_rw_t * after access) &= FAST_DATA_MASK
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
    
    // Reutnrs the rowdata without the bit packing
    inline class_ro_t *rodata() {
        auto dataBits = this->disk()->bits;
        auto resolved = dataBits & FAST_DATA_MASK;
        auto rodata = reinterpret_cast<class_ro_t*>(resolved);
        return rodata;
    }
    
    // Returns isa without the bit packing
    inline struct swift_class_t* isa() {
        auto isa = this->disk()->isa_cls;
        auto addr = reinterpret_cast<uintptr_t>(isa);
        
        return reinterpret_cast<struct swift_class_t*>(addr & FAST_DATA_MASK & 0x000007FFFFFFFFFFUL);
    }
    
    /// Checks if the current class is a swift class, if NO swift members in swift_class are unavailable
    inline bool isSwift() {
        auto bits = this->disk()->bits;
        return bits & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE) ? true : false;
    }
    
    /// Returns the name of the class (works for both Objc & Swift classes)
    const char * GetName() {
        auto clsDisk = this->disk();
        auto rodata = clsDisk->rodata();
        if (rodata == nullptr) {
            return NULL;
        }
        
        if (!rodata->validAddress()) {
            return NULL;
        }
        auto rodataDisk = rodata->disk();
        if (rodataDisk == nullptr) { return NULL; }
        auto name = rodataDisk->name;
        if (name == nullptr) {
            return NULL;
        }
        return name->disk();
    }

} swift_class;


#endif /* objc__h */


/**
 Derek notes
 
 
[0x10006dae4-0x10006daf4] protocol conformance descriptor for dsdump.someTest : dsdump.AProtocol in dsdump
int32_t*'s in dsdump`__TEXT.__swift5_proto, that point to ConformanceDescriptors
 
 
[0x10006daf4-0x10006db00] property descriptor for dsdump.someTest.blah : Swift.Optional<Swift.String>
Pointed to by the Reflection metadata field descriptor,


[0x10006db4c-0x10006db68] nominal type descriptor for dsdump.someTest
int32_t*'s in  __TEXT.__swift5_types, the "main things"

[0x100077d74-0x100077d9c] reflection metadata field descriptor dsdump.someTest
 The Fields value in the StructDescriptor

[0x100079830-0x100079848] protocol witness table for dsdump.someTest : dsdump.AProtocol in dsdump
 The GenericWitnessTable, TODO, struct is 8 bytes, but symbol is 24 bytes... da hell?

[0x100079848-0x1000798a0] value witness table for dsdump.someTest
 

[0x1000798a0-0x1000798a8] full type metadata for dsdump.someTest

[0x1000798a8-0x1000798c0] type metadata for dsdump.someTest

*/
