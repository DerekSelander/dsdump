//
//  XRMachOLibrary+Swift.m
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

// Knock out objc/runtime.h so I can use the actual headers
#ifndef _OBJC_RUNTIME_H
#define _OBJC_RUNTIME_H

//#import "objc-runtime-new.h"

#endif // OBJC_RUNTIME

#import <dlfcn.h>
#import "XRMachOLibrary+Swift.h"
#import "XRSymbolEntry.h"
#import "objc_.h"
#import "XRMachOLibrary+ObjectiveC.h"
#import "string.h"
#import <unordered_map>
#import <iostream>
#import <vector>
#import <type_traits>
#import "XRMachOLibraryCplusHelpers.h"
#import <mach-o/getsect.h>

/////////////////////////////////////////////////////////
// muwahahahahahaha going to hell for this...
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"

#define protected public
#define private public
#define class struct

#import "swift/ABI/MetadataValues.h"
#import "swift/ABI/Metadata.h"
#import "swift/ABI/TrailingObjects.h"
#import "swift/Reflection/Records.h"
#import "swift/Demangling/Demangler.h"

#undef protected
#undef private
#undef class

#pragma clang diagnostic pop
// </muwahahahahahaha going to hell for this...>
/////////////////////////////////////////////////////////


#define SWIFT_REFLECTION_METADATA_VERSION (uint16_t)(3)

/// declarations
const char *getKindString(swift::ContextDescriptorKind kind);
const char *getKindMethodString(swift::MethodDescriptorFlags::Kind kind);

using namespace std;
using namespace swift;
using namespace payload;

/// Used to correlate getter/setter methods to offsets of ivars
static NSMutableDictionary * __ivarsDictionary = nil;

/// Used to group all the Swift type references by module,
static unordered_map<const ModuleContextDescriptor*, std::vector<TypeContextDescriptor*>> moduleDescriptorDictionary;

/// They say that all descriptors will have a module, but that doesn't seem to be the case in iOS 13's apps
static std::vector<TypeContextDescriptor*> descriptorsWithNoModule;

/// Used to group the Swift protocols by module
unordered_map<const ModuleContextDescriptor *, std::vector<ProtocolDescriptor*>> moduleProtocolDictionary;

/// Fast lookup from swift type which lists all the supported protocols
static unordered_map<const ContextDescriptor*, std::vector<const ProtocolDescriptor*>> swiftProtocolsToTypesDictionary;

/***
 Swift Type Descriptors currently don't give enough deets about the methods, so using objc, to get that missing info
 This will associate the type descriptor with the corresponding class found in the ObjC classes (__objc_classlist)
 */
static unordered_map<TargetClassDescriptor<InProcess>*, swift_class*> swiftDescriptorToClassDictionary;


void wtf(uintptr_t address) {
    
    const struct segment_command_64 * seg = getsegbyname("__TEXT");
    int32_t *cur = (int32_t*)seg->vmaddr;
    for (int i = 0; i < seg->vmsize / 4; i ++) {
        uintptr_t addr = (uintptr_t)cur[i] + (uintptr_t)&cur[i];
        if (addr == address) {
            printf("Found address at %p\n", &cur[i]);
        }
    }
    
    uintptr_t *c = (uintptr_t*)seg->vmaddr;
    for (int i = 0; i < seg->vmsize / 8; i ++) {
        uintptr_t addr = (uintptr_t)c[i];
        if (addr == address) {
            printf("(64) Found address at %p\n", &cur[i]);
        }
    }
}


@implementation XRMachOLibrary (Swift)

/********************************************************************************
 // Dump symbols
 ********************************************************************************/

/**
  The swift5_types is an array of relative pointers to the different Swift types compiled,
  This needs to sort those types by the corresponding module (there could be multiple
 
  In addition, I am grabbing the associated ObjC class and pairing it with the appropriate type descriptor
  If the type descriptor is a Swift class. This is stored in swiftDescriptorToClassDictionary
 */
- (BOOL)preparseSwiftTypes {
    struct section_64* swiftTypes = payload::sectionsDict["__TEXT.__swift5_types"];
    if (!swiftTypes) {
        if (payload::sectionsDict["__TEXT.__swift4_types"]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return NO;
    }
    
    auto typeOffsets = payload::DiskWrapper<int32_t>::Cast(swiftTypes->addr);

    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        auto resolvedTypedOffset = (intptr_t)typeOffsets[i].disk() + *typeOffsets[i].disk();
        auto descriptor = reinterpret_cast<TypeContextDescriptor *>(resolvedTypedOffset);
        
        
        
//        int32_t ztypeOffset = TODISKDEREF(&ztypeOffsets[i]);
//        uintptr_t zresolvedTypedOffset = (uintptr_t)(&ztypeOffsets[i]) + ztypeOffset;
////        TypeContextDescriptor* zdescriptor = TODISK(reinterpret_cast<TypeContextDescriptor*>(zresolvedTypedOffset));
//
////        assert(zdescriptor == descriptor);
//
//
////        for (auto cur = this; true; cur = cur->Parent.get()) {
////            if (auto module = dyn_cast<TargetModuleContextDescriptor<Runtime>>(cur))
////                return module;
////        }
//
////        const ContextDescriptor* cur = LoadToDiskTranslator::Cast(descriptor);
        
        LoadToDiskTranslator<ContextDescriptor>* cur = payload::CastToDisk<ContextDescriptor>(descriptor);

        while (cur->disk()->Parent.get() != nullptr) {
            auto parent = const_cast<ContextDescriptor*>(cur->disk()->Parent.get());
            cur = payload::CastToDisk<ContextDescriptor>(parent);
        }
        
        auto module = dyn_cast<TargetModuleContextDescriptor<InProcess>>(cur->disk());
        if (module == nullptr) {
            descriptorsWithNoModule.push_back(descriptor);
            continue;
        }
        
        moduleDescriptorDictionary.emplace(module, vector<TypeContextDescriptor*>());
        moduleDescriptorDictionary.at(module).push_back(descriptor);
    }
    
    ///////////////////////
    // swiftDescriptorToClassDictionary logic
    //////////////////////////
    struct section_64* class_list = payload::sectionsDict["__DATA.__objc_classlist"];
    if (!class_list) {
        class_list = payload::sectionsDict["__DATA_CONST.__objc_classlist"];
    }
    if (!class_list) {
        perror("Couldn't find __objc_classlist segment?!\n");
        return YES;
    }

    swift_class **classes = TODISK(reinterpret_cast<swift_class**>(class_list->addr));
    int numClasses = (int)(class_list->size / PTR_SIZE);
    for (int i = 0; i < numClasses; i++) {

        auto swiftClassDisk = classes[i]->load()->disk();
        if (!(swiftClassDisk->bits & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE))) {
            continue;
        }
        
        auto descriptor = swiftClassDisk->descriptor->disk();
        swiftDescriptorToClassDictionary[descriptor] = classes[i]->load();
        
    }

    return YES;
}

- (void)dumpSwiftProtocols {
    struct section_64* swiftProtos = payload::sectionsDict["__TEXT.__swift5_protos"];
    if (!swiftProtos) {
        if (payload::sectionsDict["__TEXT.__swift4_protos"]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
    }
    
    auto protoOffsets = payload::DiskWrapper<int32_t>::Cast(swiftProtos->addr);
    for (int i = 0; i < swiftProtos->size / sizeof(uint32_t); i++) {
        auto resolvedTypedOffset = (intptr_t)protoOffsets[i].disk() + *protoOffsets[i].disk();
        auto protocol = reinterpret_cast<ProtocolDescriptor *>(resolvedTypedOffset);
        auto requirements = protocol->getRequirements();
        for (auto __unused &req : requirements) {

#warning implement me hopefully by Swift 5.2?
            // TODO: https://github.com/apple/swift/blob/659c49766be5e5cfa850713f43acc4a86f347fd8/include/swift/ABI/Metadata.h#L1717
        }
    }
    return;
}

- (void)preparseSwiftProtocols  {
    struct section_64* swiftTypes = payload::sectionsDict["__TEXT.__swift5_proto"];
    if (!swiftTypes) {
        if (payload::sectionsDict["__TEXT.__swift4_proto"]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
    }
    
    auto protoOffsets = payload::DiskWrapper<int32_t>::Cast(swiftTypes->addr)->disk();
//    auto protoOffsetsDisk = protoOffsets->disk();
    for (int i = 0; i < swiftTypes->size / sizeof(int32_t); i++) {
        auto resolvedDiskOffset = (uintptr_t)((intptr_t)(&protoOffsets[i]) + (int32_t)protoOffsets[i]);
        auto protocolConformance = reinterpret_cast<ProtocolConformanceDescriptor *>(resolvedDiskOffset);
        if (protocolConformance == nullptr) {
            continue;
        }
        auto typeDescriptor = protocolConformance->getTypeDescriptor();

#warning figure out why ARM64e gives wonky values for this particular one
        auto protocol = protocolConformance->getProtocol();
        
        if (!payload::ValidDiskAddress((uintptr_t)protocol)) {
            continue;
        }
        
        auto recast = static_cast<const ContextDescriptor*>(typeDescriptor);
        swiftProtocolsToTypesDictionary.emplace(recast, std::vector<const ProtocolDescriptor*>());
        swiftProtocolsToTypesDictionary.at(recast).push_back(protocol);
    }
    
    return;
}

- (void)dumpProtocolsForTypeContextDescriptor:(TypeContextDescriptor*)descriptor {
    auto found = swiftProtocolsToTypesDictionary.find(descriptor);
    if (found == swiftProtocolsToTypesDictionary.end()) {
        return;
    }
    putchar(',');
    auto supportedProtocols = found->second;
    auto count = supportedProtocols.size();
    for (int i = 0; i < count; i++) {
        
        auto prot = const_cast<ProtocolDescriptor*>(supportedProtocols[i]);
        if (prot == nullptr) {
            continue;
        }
        auto protocol = payload::CastToDisk<ProtocolDescriptor>(prot);
        printf(" %s", protocol->disk()->Name.get());
        if (i != count - 1) {
            putchar(',');
            putchar(' ');
        }
    }
}



- (void)dumpSwiftStructType:(StructDescriptor *)descriptor {
    // Not available till a later version of Swift reflection
}


- (void)dumpSwiftClass:(ClassDescriptor *)descriptor {

    auto it = swiftDescriptorToClassDictionary.find(descriptor);
    if (it == swiftDescriptorToClassDictionary.end()) {
        printf(" {");
        return;
    }

    // print Parent class
    [self printParentClassIfApplicable:it->second];
    
    // print Protocols
    [self dumpProtocolsForTypeContextDescriptor:descriptor];
    printf(" {");
    
    // print Propteries
    [self dumpTargetTypeContextDescriptorFields:descriptor];
    
    // print Methods
    [self dumpSwiftMethods:descriptor];
}

- (void)printParentClassIfApplicable:(swift_class*)cls {
    DSCOLOR color;
    const char *demangledName = NULL;
    std::string outDemangledstring;
    
    auto swiftClassDisk = cls->disk();
    auto superCls = swiftClassDisk->superclass;
    
    // Print out parent, is there a parent class and is it locally implemented?
    if (superCls->isNull()) { // external
        XRBindSymbol *bindSymbol = self.addressObjCDictionary[@((uintptr_t)&cls->load()->superclass)];
        auto name = bindSymbol.shortName.UTF8String;
        dshelpers::simple_demangle(name, outDemangledstring);
        demangledName = outDemangledstring.c_str();
        color = DSCOLOR_GREEN;
    } else {
        // If here, locally implemented
        auto mangledName = superCls->GetName();
        dshelpers::simple_demangle(mangledName, outDemangledstring);
        demangledName = outDemangledstring.c_str();
        color = DSCOLOR_MAGENTA;
    }
    printf(" : %s%s%s", dcolor(color), demangledName, color_end());
}

- (void)dumpSwiftTypes {
    
    // Iterate all Swift descriptors in swift5_types
    for (auto ptr = moduleDescriptorDictionary.begin(); ptr != moduleDescriptorDictionary.end(); ++ptr ) {
        auto module = ptr->first;
        auto descriptors = ptr->second;
        
        if ((module->Name.isNull() || module->isCImportedContext()) && xref_options.verbose < VERBOSE_4) {
            continue;
        }
        printf("module %s%s%s {\n", dcolor(DSCOLOR_GREEN), module->Name.get(), color_end());
        for (auto &descriptor : descriptors) {

            ContextDescriptorKind kind = descriptor->Flags.getKind();
            const char* name = descriptor->Name.get();
            printf(" %s %s%s%s", getKindString(kind), dcolor(DSCOLOR_CYAN), name, color_end());
            switch (kind) {
                case ContextDescriptorKind::Struct: {
                    auto structDescriptor = static_cast<StructDescriptor *>(descriptor);
                    printf(" {");
                    [self dumpSwiftStructType:structDescriptor];
                    [self dumpTargetTypeContextDescriptorFields:structDescriptor];
                    break;
                } case ContextDescriptorKind::Class: {
                    auto classDescriptorDisk = static_cast<ClassDescriptor *>(descriptor);
                    [self dumpSwiftClass:classDescriptorDisk];
                    break;
                } case ContextDescriptorKind::Protocol:
                    printf("TODO Protocol\n");
                    break;
                case ContextDescriptorKind::Enum: {
                    printf(" {");
                    auto enumDescriptor = static_cast<EnumDescriptor*>(descriptor);
                    [self dumpTargetTypeContextDescriptorFields:enumDescriptor];
                    break;
                }
                    
                default:
                    break;
            }
            printf(" }\n\n");
        }
        printf("}\n");
    }
    
    putchar('\n');
}


- (void)dumpSwiftMethods:(ClassDescriptor*)classDescriptor {
    
    auto methodDescriptors = classDescriptor->getMethodDescriptors();
    if (xref_options.verbose >= VERBOSE_4 && methodDescriptors.size()) {
        printf("\n%s\t// Swift methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
    }
    
    auto it = swiftDescriptorToClassDictionary.find(classDescriptor);
    if (it == swiftDescriptorToClassDictionary.end()) {
        return;
    }

    char stripped[PATH_MAX];
    snprintf(stripped, PATH_MAX, "%s%s%s", dcolor(DSCOLOR_RED), "<stripped>", color_end());
    
    for (auto &pt : methodDescriptors) {
        if (pt.Impl.isNull()) {
            continue;
        }
     
        auto resolvedMethodAddress = reinterpret_cast<uintptr_t>(FROMDISK(pt.Impl.get()));
        auto entry = self.symbolEntry[@(resolvedMethodAddress)];
        
        std::string outDemangledString;
        dshelpers::simple_demangle(entry.name, outDemangledString);
        
        auto flags = pt.Flags;
        bool isInstanceMethod = flags.isInstance();

        const char *resolvedMethodName = outDemangledString.length() == 0 ? stripped : outDemangledString.c_str();
        printf("\t%s%p%s%s %s func %s%s", dcolor(DSCOLOR_GRAY), (void*)resolvedMethodAddress, color_end(), dcolor(DSCOLOR_BOLD), isInstanceMethod ? "" : " class", resolvedMethodName, color_end());
        if (xref_options.verbose >= VERBOSE_3) {
            printf(" %s// %s %s", dcolor(DSCOLOR_GRAY), getKindMethodString(flags.getKind()), color_end());
        }
        
        putchar('\n');
    }
}

/// AKA properties
- (void)dumpTargetTypeContextDescriptorFields:(TypeContextDescriptor*)descriptorDisk {

    auto fields = descriptorDisk->Fields.get();
    if (!fields) {
        return;
    }
    
    auto numFields = fields->NumFields;
    if (xref_options.verbose >= VERBOSE_4 && numFields > 0) {
        printf("\n%s\t// Properties%s", dcolor(DSCOLOR_GRAY), color_end());
    }
    if (numFields) {
        putchar('\n');
    }
    if (!descriptorDisk->isReflectable()) {
        return;
    }

    ContextDescriptorKind kind = descriptorDisk->Flags.getKind();
    auto fieldRecords = descriptorDisk->Fields.get()->getFields();

    for (auto &pt : fieldRecords) {
        const char * declarationNameType;
        
        declarationNameType = kind == ContextDescriptorKind::Enum ? "case" : pt.Flags.isVar() ? "var" : "let";
        auto mangledNameBase = pt.MangledTypeName.get();
        StringRef mangledName = (mangledNameBase == nullptr) ? StringRef("") : makeSymbolicMangledNameStringRef(pt.MangledTypeName.get());
        auto fieldName = pt.FieldName.get();
        
        std::string str;
        const char* resolvedSymbolicReference = dshelpers::simple_type(mangledName, str);
        
        
        printf("\t%s%s %s %s %s%s\n", dcolor(DSCOLOR_GREEN),
                                           declarationNameType,
                                           fieldName,
                                           !mangledName.empty() ? ":" : "",
                                           resolvedSymbolicReference,
                                           color_end());
    }
    
    putchar('\n');
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

const char *getKindMethodString(swift::MethodDescriptorFlags::Kind kind) {
    switch (kind) {
            /// This context descriptor represents a module.
        case swift::MethodDescriptorFlags::Kind::Method:
            return "method";
        case swift::MethodDescriptorFlags::Kind::Init:
            return "init";
        case swift::MethodDescriptorFlags::Kind::Getter:
            return "getter";
        case swift::MethodDescriptorFlags::Kind::Setter:
            return "setter";
        case swift::MethodDescriptorFlags::Kind::ModifyCoroutine:
            return "modifyCoroutine";
        case swift::MethodDescriptorFlags::Kind::ReadCoroutine:
            return "readCoroutine";
    }
    
    return "<unknown>";
}
