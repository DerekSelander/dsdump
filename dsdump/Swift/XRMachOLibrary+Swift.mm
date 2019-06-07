//
//  XRMachOLibrary+Swift.m
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <dlfcn.h>
#import "XRMachOLibrary+Swift.h"
#import "objc_.h"
#import "string.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"
#import "swift/Reflection/Records.h"

#pragma clang diagnostic pop
#import "XRMachOLibraryCplusHelpers.h"


const char *getKindString(swift::ContextDescriptorKind kind);
static char *demangledName(const char* mangledTypeName);

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

    if (!ds_xcselect_get_developer_dir_path)  {
        return NO;
    }


    // Hokay found the function xcselect_get_developer_dir_path, consult that for path...
    char xcode_path[PATH_MAX];
    uintptr_t dunno1, dunno2, dunno3;
    const char * libxcrun_path = "/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-demangle";
    ds_xcselect_get_developer_dir_path(xcode_path, PATH_MAX, &dunno1, &dunno2, &dunno3);
    
    
    // Append path component to location of swift-demangle
    strncpy(&xcode_path[strlen(xcode_path)], libxcrun_path, strlen(libxcrun_path) + 1);

    

    
    return YES;
}
#define SWIFT_REFLECTION_METADATA_VERSION (uint16_t)(3)
- (void)checkCorrectReflectionVersion {
//    ___swift_reflection_version
    char *strtab = self.str_symbols;
    for (int i = self.dysymtab->ilocalsym; i < self.dysymtab->nlocalsym + self.dysymtab->ilocalsym; i++) {
        struct nlist_64 symbol = self.symbols[i];
        if ( strcmp(&strtab[symbol.n_un.n_strx], "___swift_reflection_version") == 0) {
            uint16_t reflection_version = *(uint16_t *)DATABUF(symbol.n_value + self.file_offset);
            if (reflection_version > SWIFT_REFLECTION_METADATA_VERSION) {
                printf("%sNew swift reflection version, tell Derek what binary you're using\n%s", dcolor(DSCOLOR_RED), color_end());
            }
            return;
        }
    }
}

- (void)dumpSwiftTypes {
    

    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
//    if (!swiftTypes) {
//        swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
//    }
    
    if (!swiftTypes) {
        if ([self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
        
    }
    
    int32_t *typeOffsets = (int32_t*)swiftTypes->addr;
    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        
        int32_t typeOffset = FROMDISK(&typeOffsets[i]);
        uintptr_t resolvedTypedOffset = (uintptr_t)(&typeOffsets[i]) + typeOffset;
        TypeContextDescriptor* descriptor = FROMDISK_PTR(reinterpret_cast<TypeContextDescriptor*>(resolvedTypedOffset));

        ContextDescriptorKind kind = descriptor->Flags.getKind();
        const char* name = descriptor->Name.get();
//        auto fieldDescriptor = descriptor->Fields.get();

//        auto parentDescriptor = descriptor->Parent.get();
//        auto parentKind = parentDescriptor->Flags.getKind();
        
        
        printf("%s %s", getKindString(kind), name);
//        auto mangle = fieldDescriptor->getMangledTypeName(0);
        
//        auto val = descriptor->Name.get();
        switch (kind) {
            case ContextDescriptorKind::Struct: {

                TargetStructDescriptor<InProcess>* structDescriptor = static_cast<TargetStructDescriptor<InProcess> *>(descriptor);
                [self dumpTargetTypeContextDescriptorFields:structDescriptor];

                
                break;
            } case ContextDescriptorKind::Class: {
                TargetClassDescriptor<InProcess>* classDescriptor = static_cast<TargetClassDescriptor<InProcess> *>(descriptor);

               
                [self dumpTargetTypeContextDescriptorFields:classDescriptor];
                break;
                
            } case ContextDescriptorKind::Protocol:
                break;
                
            case ContextDescriptorKind::Enum: {
                TargetEnumDescriptor<InProcess>* enumDescriptor = static_cast<TargetEnumDescriptor<InProcess> *>(descriptor);
                
                [self dumpTargetTypeContextDescriptorFields:enumDescriptor];
            }
                break;
            default:
                break;
        }
        

     
        putchar('}');
        putchar('\n');
        putchar('\n');
        
        
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


- (void)dumpTargetTypeContextDescriptorFields:(TypeContextDescriptor*)contextDescriptor {
    putchar(' ');
    putchar('{');
    
    auto fields = contextDescriptor->Fields.get();
    if (!fields) { return;  }
    auto numFields = fields->NumFields;
    if (numFields) {
        putchar('\n');
    }
    if (!contextDescriptor->isReflectable()) {
        return;
    }

    ContextDescriptorKind kind = contextDescriptor->Flags.getKind();

    auto fieldDescriptor = contextDescriptor->Fields.get()->getFields();

    for (auto &pt : fieldDescriptor) {
        
        const char * declarationNameType;
        if (kind ==  ContextDescriptorKind::Enum) {
            declarationNameType = "case";
        } else {
            declarationNameType = pt.Flags.isVar() ? "var" : "let";
        }

        auto mangledTypeName = (pt.MangledTypeName.get());
        auto fieldName = (pt.FieldName.get());

        printf("\t%s %s %s %s\n", declarationNameType, fieldName, mangledTypeName ? ":" : "", mangledTypeName? demangledName(mangledTypeName) : "");
    }
    
}

@end


static char *demangledName(const char* mangledTypeName) {
    static char str[PATH_MAX];
//    assert(mangledTypeName[0] == 'S');
    int cur = 0;
    for (int i = 0; i < strlen(mangledTypeName); i++) {
        if (mangledTypeName[i++] == 'S') {
            
            if (mangledTypeName[i] == 'i') { strncpy(&str[cur], "Int", 3); cur+=3; }
            else if (mangledTypeName[i] == 'S') { strncpy(&str[cur], "String", 6); cur+=6; }
            else if (mangledTypeName[i] == 'g') { strncpy(&str[cur], "?", 1); cur+=1; }
            else if (mangledTypeName[i] == 'd') { strncpy(&str[cur], "Double", 1); cur+=6; }
            else if (mangledTypeName[i] == 'f') { strncpy(&str[cur], "Float", 1); cur+=5; }
            else if (mangledTypeName[i] == 'o') { // Class type?
                char *end;
                long count = strtol(&mangledTypeName[++i], &end, 10);
                assert(end);
//                cur += (end - &str[cur]);
                strncpy(&str[cur], end, count);
                cur += count;
                
                i++; // end has C
//                strncpy(&str[cur], "?", 1); cur+=1;
            }
            else {
                printf("%snew type %s!!%s\n", dcolor(DSCOLOR_RED), mangledTypeName, color_end());
            }
        }
        
    }
    str[cur] = '\00';
    return str;
}
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

const char *getKindString(swift::ContextDescriptorKind kind) {
    switch (kind) {
            /// This context descriptor represents a module.
        case swift::ContextDescriptorKind::Module:
            return "module";
        case swift::ContextDescriptorKind::Extension:
            return "extension";

        case swift::ContextDescriptorKind::Anonymous:
            return "anonymous";
        case swift::ContextDescriptorKind::OpaqueType:
            return "dunno";
        case swift::ContextDescriptorKind::Class:
            return "class";
        case swift::ContextDescriptorKind::Struct:
            return "struct";
        case swift::ContextDescriptorKind::Enum:
            return "enum";
        case swift::ContextDescriptorKind::Protocol:
            return "protocol";
        case swift::ContextDescriptorKind::Type_Last:
            return "last<unknown>";
//            Anonymous = 2,
//
//            /// This context descriptor represents a protocol context.
//            Protocol = 3,
//
//            /// This context descriptor represents an opaque type alias.
//            OpaqueType = 4,
//
//            /// First kind that represents a type of any sort.
//            Type_First = 16,
//
//            /// This context descriptor represents a class.
//            Class = Type_First,
//
//            /// This context descriptor represents a struct.
//            Struct = Type_First + 1,
//
//            /// This context descriptor represents an enum.
//            Enum = Type_First + 2,
//
//            /// Last kind that represents a type of any sort.
//            Type_Last = 31,
    }
    
    return "<unknown>";
}
