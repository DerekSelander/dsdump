//
//  XRMachOLibrary+Swift.m
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+Swift.h"
#import "objc_.h"
#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"
#import <dlfcn.h>

const char *getKindString(uint32_t kind);

using namespace swift;

@implementation XRMachOLibrary (Swift)

static void(*ds_xcselect_get_developer_dir_path)(const char *ptr, size_t length, uintptr_t *a, uintptr_t *b, uintptr_t *c);

- (BOOL)loadSwiftDemangle {
    
    // First we need to figure out where the hey Xcode is, so consult libxcselect.dylib...
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        void* handle = dlopen("/usr/lib/libxcselect.dylib", RTLD_NOW);
        ds_xcselect_get_developer_dir_path = (void(*)(const char *ptr, size_t length, uintptr_t *a, uintptr_t *b, uintptr_t *c))dlsym(handle, "xcselect_get_developer_dir_path");
    });

    if (!ds_xcselect_get_developer_dir_path)  { return NO; }


    // Hokay found the function xcselect_get_developer_dir_path, consult that for path...
    char xcode_path[PATH_MAX];
    uintptr_t dunno1, dunno2, dunno3;
    const char * libxcrun_path = "/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle";
    ds_xcselect_get_developer_dir_path(xcode_path, PATH_MAX, &dunno1, &dunno2, &dunno3);
    
    
    // Append path component to location of swift-demangle
    strncpy(&xcode_path[strlen(xcode_path)], libxcrun_path, strlen(libxcrun_path) + 1);

    

    
    return YES;
}

- (void)dumpSwiftTypes {
    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue];
    if (!swiftTypes) {
        swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
    }
    
    if (!swiftTypes) { return; }
    
    int32_t *typeOffsets = (int32_t*)swiftTypes->addr;
    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        
        
        int32_t typeOffset = Resolve32BitAddress(&typeOffsets[i]);
        uintptr_t resolvedTypedOffset = (uintptr_t)(&typeOffsets[i]) + typeOffset;
        TypeContextDescriptor* descriptor = reinterpret_cast<TypeContextDescriptor*>(resolvedTypedOffset);
        ContextDescriptorKind kind = descriptor->Flags.getKind();
        auto val = descriptor->Name.get();
        switch (kind) {
            case ContextDescriptorKind::Struct:
//                static_cast<TargetClassDescriptor<int32_t>*>(descriptor);
//                TargetClassDescriptor<swift::runtime> f;
//                descriptor
                
                printf("HI");
                break;
            case ContextDescriptorKind::Class:
                break;
                
            case ContextDescriptorKind::Protocol:
                break;
            default:
                break;
        }
        printf("yay\n");
        
        
//        // flags
////        uintptr_t flags_FO =  [self translateLoadAddressToFileOffset:offsetof(swift_descriptor, flags) + (uintptr_t)descriptor  useFatOffset:YES];
////        uint32_t flagss = *(uint32_t *)DATABUF(flags_FO);
//        uint32_t flags = Resolve32BitAddress(offsetof(swift_descriptor, flags) + (uintptr_t)descriptor);
//        uint32_t kind = DescriptorFlagsGetKind(flags);
//        int32_t parentTypeOffset = Resolve32BitAddress((uintptr_t)descriptor + offsetof(swift_descriptor, parentOffset));
//
//
//        uintptr_t resolvedParentTypeOffset = (uintptr_t)descriptor + offsetof(swift_descriptor, parentOffset) + parentTypeOffset;
//        swift_descriptor *parent_descriptor = (swift_descriptor *)resolvedParentTypeOffset;
//
//        int32_t parentNamedOffset = Resolve32BitAddress((uintptr_t)parent_descriptor + offsetof(swift_descriptor, namedOffset));
//        uintptr_t parentNamedOffset_FO = [self translateLoadAddressToFileOffset:offsetof(swift_descriptor, namedOffset) + (uintptr_t)parent_descriptor + parentNamedOffset useFatOffset:YES];
//        char * parentName = (char*)DATABUF(parentNamedOffset_FO);
//
//        // name
//        int32_t namedOffset = Resolve32BitAddress((uintptr_t)&descriptor->namedOffset);
//        uintptr_t namedOffset_FO = [self translateLoadAddressToFileOffset:offsetof(swift_descriptor, namedOffset) + (uintptr_t)descriptor + namedOffset useFatOffset:YES];
//        char * name = (char*)DATABUF(namedOffset_FO);
//
//        // Parent flags
//        uint32_t parentFlags = Resolve32BitAddress(offsetof(swift_descriptor, flags) + (uintptr_t)parent_descriptor);
//        uint32_t parentKind = DescriptorFlagsGetKind(parentFlags);
//
//        uintptr_t ptr = Resolve64BitAddress(offsetof(swift_descriptor, accessFunctionOffset) + (uintptr_t)descriptor);
//        printf("%s %s : %s (%s)", getKindString(kind), name, parentName, getKindString(parentKind));
//        putchar('{');
//
//
////        for (int j = 0; j < fieldCount; j++) {
////
////        }
//        putchar('}');
//        putchar('\n');
    }
}


//- (const char *)demangledSwiftName:(const char*)name {


/*
 // expects code to be linked to /usr/lib/xcselect.dylib ("xcode-select -p" equivalent)
 static char *xcode_path() {
 char *input = calloc(0x400, sizeof(char));
 char dunno1, dunno2, dunno3;
 void* xcselect_get_developer_dir_path(char *ptr, size_t length, char *a, char*b, char *c);
 xcselect_get_developer_dir_path(input, 0x400, &dunno1, &dunno2, &dunno3);
 return input;
 }
 */
@end

/*
 /// Kinds of context descriptor.
 enum class ContextDescriptorKind : uint8_t {
 /// This context descriptor represents a module.
 Module = 0,
 
 /// This context descriptor represents an extension.
 Extension = 1,
 
 /// This context descriptor represents an anonymous possibly-generic context
 /// such as a function body.
 Anonymous = 2,
 
 /// This context descriptor represents a protocol context.
 Protocol = 3,
 
 /// This context descriptor represents an opaque type alias.
 OpaqueType = 4,
 
 /// First kind that represents a type of any sort.
 Type_First = 16,
 
 /// This context descriptor represents a class.
 Class = Type_First,
 
 /// This context descriptor represents a struct.
 Struct = Type_First + 1,
 
 /// This context descriptor represents an enum.
 Enum = Type_First + 2,
 
 /// Last kind that represents a type of any sort.
 Type_Last = 31,
 };

 */

const char *getKindString(uint32_t kind) {
    switch (kind) {
        case 0:
            return "class";
        case 1:
            return "struct";
        case 2:
            return "enum";
        case 3:
            return "optional";
        case 8:
            return "opaque";
        case 9:
            return "tuple";
        case 10:
            return "function";
        case 12:
            return "protocol";
        case 13:
            return "metatype";
        case 14:
            return "objc";
        case 15:
            return "ext metatype";
        default:
            break;
    }
    
    return "<unknown>";
}
