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
#import <unordered_map>
#import <vector>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"
#import "swift/Reflection/Records.h"
#import "swift/Demangling/Demangler.h"

#pragma clang diagnostic pop
#import "XRMachOLibraryCplusHelpers.h"

#define SWIFT_REFLECTION_METADATA_VERSION (uint16_t)(3)

/// declarations
const char *getKindString(swift::ContextDescriptorKind kind);
static char *demangledName(const char* mangledTypeName);

using namespace std;
using namespace swift;

// Used to sort all the type references by module
using DescriptorDict =  unordered_map<const TargetModuleContextDescriptor<InProcess>*, vector<TypeContextDescriptor*>>;
static DescriptorDict descriptorDict;

static auto simplifiedOptions = swift::Demangle::DemangleOptions::SimplifiedUIDemangleOptions();
static auto context = Context();

@implementation XRMachOLibrary (Swift)

/********************************************************************************
 // Dump symbols
 ********************************************************************************/

- (BOOL)preparseSwiftTypes {
    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
    if (!swiftTypes) {
        if ([self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return NO;
    }
    
    int32_t *typeOffsets = (int32_t*)swiftTypes->addr;
    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        
        int32_t typeOffset = FROMDISK(&typeOffsets[i]);
        uintptr_t resolvedTypedOffset = (uintptr_t)(&typeOffsets[i]) + typeOffset;
        // TODO RE-add FROMDISK_PTR
        TypeContextDescriptor* descriptor = FROMDISK_PTR(reinterpret_cast<TypeContextDescriptor*>(resolvedTypedOffset));

        const TargetModuleContextDescriptor<InProcess> * module = descriptor->getModuleContext();
        descriptorDict.emplace(module, vector<TypeContextDescriptor*>());
        descriptorDict.at(module).push_back(descriptor);
    }
    
    return YES;
}

//- (void)checkCorrectReflectionVersion {
////    ___swift_reflection_version
//    char *strtab = self.str_symbols;
//    for (int i = self.dysymtab->ilocalsym; i < self.dysymtab->nlocalsym + self.dysymtab->ilocalsym; i++) {
//        struct nlist_64 symbol = self.symbols[i];
//        if ( strcmp(&strtab[symbol.n_un.n_strx], "___swift_reflection_version") == 0) {
//            uint16_t reflection_version = *(uint16_t *)DATABUF(symbol.n_value + self.file_offset);
//            if (reflection_version > SWIFT_REFLECTION_METADATA_VERSION) {
//                printf("%sNew swift reflection version, tell Derek what binary you're using\n%s", dcolor(DSCOLOR_RED), color_end());
//            }
//            return;
//        }
//    }
//}

- (void)dumpSwiftTypes {
    

    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
    if (!swiftTypes) {
        if ([self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
    }
    

    for ( auto ptr = descriptorDict.begin(); ptr != descriptorDict.end(); ++ptr ) {
        
        
        auto module = ptr->first;
        if ((module->Name.isNull() || module->isCImportedContext()) && xref_options.verbose < VERBOSE_4) {
            continue;
        }
        printf("module %s%s%s {\n", dcolor(DSCOLOR_GREEN), module->Name.get(), color_end());
        auto descriptors = ptr->second;
        
        for (auto &descriptor : descriptors) {

            
            ContextDescriptorKind kind = descriptor->Flags.getKind();
            const char* name = descriptor->Name.get();
            printf(" %s %s%s%s", getKindString(kind), dcolor(DSCOLOR_CYAN), name, color_end());

            switch (kind) {
                case ContextDescriptorKind::Struct: {
                    
                    TargetStructDescriptor<InProcess>* structDescriptor = static_cast<TargetStructDescriptor<InProcess> *>(descriptor);
                    [self dumpTargetTypeContextDescriptorFields:structDescriptor];
                    
                    
                    break;
                } case ContextDescriptorKind::Class: {
                    TargetClassDescriptor<InProcess>* classDescriptor = static_cast<TargetClassDescriptor<InProcess> *>(descriptor);
                    
                    auto  cls = classDescriptor->getMethodDescriptors();
                 
                    if (!classDescriptor->SuperclassType.isNull()) {
                        auto superclassMangledName = classDescriptor->SuperclassType.get();
                        auto superclassName = context.demangleTypeAsString(superclassMangledName, simplifiedOptions);
                        auto someClass = classDescriptor->getObjCResilientClassStub();
                        
                        printf(" : %s", superclassName.c_str());
                    }
                    if (classDescriptor->hasResilientSuperclass()) {
                        printf("yay!");
                    }
                        
                    [self dumpTargetTypeContextDescriptorFields:classDescriptor];
                    [self dumpSwiftMethods:classDescriptor];
                    break;
                    
                } case ContextDescriptorKind::Protocol:
                    break;
                    
                case ContextDescriptorKind::Enum: {
                    TargetEnumDescriptor<InProcess>* enumDescriptor = static_cast<TargetEnumDescriptor<InProcess> *>(descriptor);
                    
                    [self dumpTargetTypeContextDescriptorFields:enumDescriptor];
                    break;
                }
                default:
                    break;
            }
            putchar(' ');
            putchar('}');
            putchar('\n');
            putchar('\n');
            
        }
        putchar('}');
    }
}


- (void)dumpSwiftMethods:(TargetClassDescriptor<InProcess>*)classDescriptor {
    
    auto methodDescriptors = classDescriptor->getMethodDescriptors();
    if (xref_options.verbose >= VERBOSE_3 && methodDescriptors.size()) {
        printf("\n%s\t// Swift methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
    }
}

/// AKA properties
- (void)dumpTargetTypeContextDescriptorFields:(TypeContextDescriptor*)contextDescriptor {
    putchar(' ');
    putchar('{');
    auto fields = contextDescriptor->Fields.get();
    if (!fields) { return;  }
    auto numFields = fields->NumFields;
    if (xref_options.verbose >= VERBOSE_3 && numFields > 0) {
        printf("\n%s\t// Properties%s", dcolor(DSCOLOR_GRAY), color_end());
    }
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
     
        
        std::string demangledName;
        if (mangledTypeName) {
            auto strref = StringRef(mangledTypeName);
            demangledName = context.demangleTypeAsString(strref, simplifiedOptions);
        }
        
        printf("\t%s %s %s %s \n", declarationNameType, fieldName, mangledTypeName ? ":" : "", mangledTypeName? demangledName.c_str() : "");
    }
    
}

@end


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
    }
    
    return "<unknown>";
}
