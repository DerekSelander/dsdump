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
#import <unordered_map>
#import <iostream>
#import <vector>
#import <type_traits>
#import <mach-o/getsect.h>

#import "string.h"
#import "XRMachOLibrary+Swift.h"
#import "XRSymbolEntry.h"
#import "objc_.h"
#import "XRMachOLibrary+ObjectiveC.h"
#import "XRMachOLibraryCplusHelpers.h"
#import "XRMachOLibrary+Disassemble.h"

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


const char *getProtocolRequirementName(ProtocolRequirementFlags::Kind kind);

const char * resolveExternalTypeDescriptorIfNeeded(const char *base, bool &resolved);

/********************************************************************************
// Debugging symbols
********************************************************************************/

#if DEBUG
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
        uintptr_t addr = (uintptr_t)c[i] + (uintptr_t)&c[i];
        if (addr == address) {
            printf("(64) Found address at %p\n", &cur[i]);
        }
    }
}

void test(uintptr_t address) {
    int32_t *cur = (int32_t *)address;
    printf("resolved: %p\n", (void*)((uintptr_t)*cur + uintptr_t(address)) );
}

#endif // DEBUG

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
        auto cur = payload::CastToDisk<ContextDescriptor>(descriptor);

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
    if (!class_list) { // OK, no ObjC classes in here
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
        swiftDescriptorToClassDictionary[descriptor] = classes[i]->disk();
    }

    return YES;
}

- (void)dumpSwiftProtocols {
    // swift5_protos
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
        ContextDescriptor* parent = const_cast<ContextDescriptor*>(protocol->Parent.get());
        
        auto name = protocol->Name.get();
        if (!ContainsFilteredWords(name)) {
            continue;
        }
        
        const char *moduleName = "";
        auto moduleContext = protocol->getModuleContext();
        if (moduleContext) {
            moduleName = moduleContext->Name.get();
        }
        
        printf(" protocol %s%s%s.%s%s%s", dcolor(DSCOLOR_YELLOW_LIGHT), moduleName, color_end(), dcolor(DSCOLOR_YELLOW), protocol->Name.get(), color_end());
        
        if (xref_options.verbose == VERBOSE_NONE) {
            putchar('\n');
            continue;
        }
        
        while (parent != nullptr && parent->getKind() == ContextDescriptorKind::Protocol) {
            auto parentProtocol = reinterpret_cast<const ProtocolDescriptor *>(parent);
            printf(", %s", parentProtocol->Name.get());
            parent = const_cast<ContextDescriptor*>(parent->Parent.get());
        }
        
        
        if (xref_options.verbose < VERBOSE_3) {
            putchar('\n');
            continue;
        }
        printf(" %s// %zu requirements%s", dcolor(DSCOLOR_GRAY), requirements.size(), color_end());

        if (xref_options.verbose <= VERBOSE_4) {
            putchar('\n');
            continue;
        }
        printf("\n {\n");
        for (auto __unused &req : requirements) {
            auto flags = req.Flags;
            auto kind = flags.getKind();
            auto isInstance = flags.isInstance();
            
            if (xref_options.verbose > VERBOSE_4) {
                printf("\t// %s%s\n", isInstance ? "" : "class ", getProtocolRequirementName(kind));
            }
            
#warning implement me hopefully by Swift 6.0?
            // Add more code here when Swift reflection developer adds names to requirements
            // TODO: https://github.com/apple/swift/blob/659c49766be5e5cfa850713f43acc4a86f347fd8/include/swift/ABI/Metadata.h#L1717
        }
        printf(" }\n");
    }
    
    if (swiftProtos->size && xref_options.verbose >= VERBOSE_3) {
        printf("\n");
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
    
    auto kind = descriptor->getKind();
    if (kind == ContextDescriptorKind::Struct) {
        putchar(':');
    } else {
        putchar(',');
    }
    
    auto supportedProtocols = found->second;
    auto count = supportedProtocols.size();
    for (int i = 0; i < count; i++) {
        
        auto prot = const_cast<ProtocolDescriptor*>(supportedProtocols[i]);
        if (prot == nullptr) {
            continue;
        }
        auto protocol = payload::CastToDisk<ProtocolDescriptor>(prot);
        printf(" %s%s%s", dcolor(DSCOLOR_YELLOW_LIGHT), protocol->disk()->Name.get(), color_end());
        if (i != count - 1) {
            putchar(',');
            putchar(' ');
        }
    }
}



- (void)dumpSwiftStruct:(StructDescriptor *)descriptor {
    // Not available till a later version of Swift reflection :|
    if (xref_options.verbose < VERBOSE_3) {
        putchar('\n');
        return;
    }
    [self dumpProtocolsForTypeContextDescriptor:descriptor];
    printf(" {");
    
    [self dumpTargetTypeContextDescriptorFields:descriptor];
    printf(" }\n\n");
}


- (void)dumpSwiftClass:(ClassDescriptor *)descriptor module:(const ModuleContextDescriptor*)module {

    if (xref_options.verbose == VERBOSE_NONE) {
        putchar('\n');
        return;
    }
    auto it = swiftDescriptorToClassDictionary.find(descriptor);
    if (it == swiftDescriptorToClassDictionary.end()) {
        if (xref_options.verbose >= VERBOSE_3) {
            printf(" {");
        }
        putchar('\n');
        return;
    }

    // print Parent class
    [self printParentClassIfApplicable:it->second];
    
    // print Protocols
    if (xref_options.verbose < VERBOSE_2) {
        putchar('\n');
        return;
    }
    [self dumpProtocolsForTypeContextDescriptor:descriptor];
    
    // print Propteries
    if (xref_options.verbose < VERBOSE_3) {
        putchar('\n');
        return;
    }
    printf(" {");
    [self dumpTargetTypeContextDescriptorFields:descriptor];
    
    
    // print objc bridge methods
    if (xref_options.verbose >= VERBOSE_4) {
        [self extractSwiftCClassObjCMethods:descriptor module:module];
    }
    
    // print pure Swift Methods
    [self dumpSwiftMethods:descriptor];
    
    printf(" }\n\n");
}

- (void)printParentClassIfApplicable:(swift_class*)cls {
    DSCOLOR color;
    const char *demangledName = NULL;
    std::string outDemangledstring;
    
    auto swiftClassDisk = cls->disk();
    auto superCls = swiftClassDisk->superclass;
    
    char *libName = NULL;
    
    // Print out parent, is there a parent class and is it locally implemented?
    if (superCls->isNull()) { // external
        XRBindSymbol *bindSymbol = self.addressObjCDictionary[@((uintptr_t)&cls->load()->superclass)];
        auto name = bindSymbol.shortName.UTF8String;
        dshelpers::simple_demangle(name, outDemangledstring);
        demangledName = outDemangledstring.c_str();
        color = DSCOLOR_GREEN;
        
        libName = (char*)self.depdencies[bindSymbol.libOrdinal].UTF8String;
           
    } else {
        // If here, locally implemented
        auto mangledName = superCls->GetName();
        dshelpers::simple_demangle(mangledName, outDemangledstring);
        demangledName = outDemangledstring.c_str();
        color = DSCOLOR_MAGENTA;
    }
    printf(" : %s%s%s", dcolor(color), demangledName, color_end());
    if (libName && xref_options.verbose >= VERBOSE_3) {
        printf(" %s%s%s", dcolor(DSCOLOR_YELLOW), libName, color_end());
    }
}

- (void)dumpDescriptors:(const std::vector<TypeContextDescriptor *> &)descriptors module:(const ModuleContextDescriptor* )module {
    const char* moduleName = NULL;
    if (module) {
      moduleName = module->Name.get();
    }
    for (auto &descriptor : descriptors) {
        
        ContextDescriptorKind kind = descriptor->Flags.getKind();
        const char* name = descriptor->Name.get();
        if (!ContainsFilteredWords(name)) {
            continue;
        }
        if (moduleName) {
            printf(" %s %s%s%s.%s%s%s", getKindString(kind), dcolor(DSCOLOR_CYAN_LIGHT), moduleName, color_end(), dcolor(DSCOLOR_CYAN), name, color_end());
        } else {
            printf(" %s %s%s%s", getKindString(kind), dcolor(DSCOLOR_CYAN), name, color_end());
        }
        
//        if (xref_options.verbose == VERBOSE_NONE) {
//            putchar('\n');
//            continue;
//        }
        switch (kind) {
            case ContextDescriptorKind::Struct: {
                auto structDescriptor = static_cast<StructDescriptor *>(descriptor);
                [self dumpSwiftStruct:structDescriptor];
                break;
            } case ContextDescriptorKind::Class: {
                auto classDescriptorDisk = static_cast<ClassDescriptor *>(descriptor);
                [self dumpSwiftClass:classDescriptorDisk module:module];
                break;
            } case ContextDescriptorKind::Protocol:
                printf("TODO Protocol\n");
                break;
            case ContextDescriptorKind::Enum: {
                auto enumDescriptor = static_cast<EnumDescriptor*>(descriptor);
                [self dumpSwiftEnum:enumDescriptor];
                break;
            }
                
            default:
                break;
        }
    }
}

- (void)dumpSwiftEnum:(EnumDescriptor*)enumDescriptor {
    if (xref_options.verbose < VERBOSE_3) {
        putchar('\n');
        return;
    }
    
    printf(" {");
    [self dumpTargetTypeContextDescriptorFields:enumDescriptor];
    printf(" }\n\n");
}

- (void)dumpSwiftTypes {
    [self dumpSwiftProtocols];
    
    // Iterate all Swift descriptors in swift5_types
    for (auto ptr = moduleDescriptorDictionary.begin(); ptr != moduleDescriptorDictionary.end(); ++ptr ) {
        auto module = ptr->first;
        auto descriptors = ptr->second;

        [self dumpDescriptors:descriptors module:module];
    }
    
    [self dumpDescriptors:descriptorsWithNoModule module:nullptr];
    putchar('\n');
}


- (void)dumpSwiftMethods:(ClassDescriptor*)classDescriptor {
    auto methodDescriptors = classDescriptor->getMethodDescriptors();
    if (xref_options.verbose >= VERBOSE_4 && methodDescriptors.size()) {
        printf("\n%s\t// Swift methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
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

- (ivar *)extractSwiftObjCIvars:(swift::TypeContextDescriptor *)descriptorDisk {
    auto castDescriptor = payload::CastToDisk<ClassDescriptor>(descriptorDisk)->disk();
    auto got = swiftDescriptorToClassDictionary.find(castDescriptor);
    if (got == swiftDescriptorToClassDictionary.end()) {
        return NULL;
    }
    auto swiftClassDisk = got->second->disk();
    auto rodata = swiftClassDisk->rodata()->disk();
    auto rodataDisk = rodata->disk();
    if (rodataDisk->ivarList == nullptr) {
        return NULL;
    }
    
    auto ivarList = rodataDisk->ivarList;
    if (ivarList == nullptr) {
        return NULL;
    }
    
    auto ivarListDisk = ivarList->disk();
    auto ivarsPtr = &ivarListDisk->first_ivar;
    return ivarsPtr->disk();
}

- (void)extractSwiftCClassObjCMethods:(swift::TypeContextDescriptor *)descriptorDisk module:(const ModuleContextDescriptor* )module {
    auto castDescriptor = payload::CastToDisk<ClassDescriptor>(descriptorDisk)->disk();
    auto got = swiftDescriptorToClassDictionary.find(castDescriptor);
    if (got == swiftDescriptorToClassDictionary.end()) {
        return;
    }
    auto swiftClassDisk = got->second->disk();
    auto rodata = swiftClassDisk->rodata()->disk();
    auto rodataDisk = rodata->disk();
    
    auto methodList = rodataDisk->baseMethodList;    
    if (methodList == nullptr) {
        return;
    }
    auto methodListDisk = methodList->disk();
    auto methodsPtr = &methodListDisk->first_method;
    printf("\n");
    
    if (xref_options.verbose >= VERBOSE_4) {
        printf("\t%s// ObjC -> Swift bridged methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
    }
    for (int i  = 0; i < methodListDisk->count; i++) {
        auto &method = methodsPtr[i];
        auto imp = method.imp->load();
        const char *resolvedName = NULL;
        char name[PATH_MAX];
        
        auto entry = self.symbolEntry[@((uintptr_t)imp)];
        std:string str;
        
        // Can we find this in the symbol table?
        if (entry && entry.name) {
            dshelpers::simple_demangle(entry.name, str);
            resolvedName = str.c_str();
        }
        
        // No symbol table info to grab? Fuck it, regenerate via ObjC info instead
        if (!resolvedName) {
            snprintf(name, PATH_MAX, "@objc %s.%s", descriptorDisk->Name.get(), method.name->disk());
            resolvedName = name;
            printf("\t%s%p%s  %s%s%s %s<stripped>%s\n", dcolor(DSCOLOR_GRAY), imp, color_end(), dcolor(DSCOLOR_BOLD), resolvedName, color_end(), dcolor(DSCOLOR_RED), color_end());
        } else {
            printf("\t%s%p%s  %s%s%s\n", dcolor(DSCOLOR_GRAY), imp, color_end(), dcolor(DSCOLOR_BOLD), resolvedName, color_end());
        }
    }
}


/// AKA properties
- (void)dumpTargetTypeContextDescriptorFields:(TypeContextDescriptor*)descriptorDisk {
    
    if (xref_options.verbose == VERBOSE_NONE) {
        return;
    }

    auto fields = descriptorDisk->Fields.get();
    if (!fields) {
        return;
    }
    
    auto accessFuncPtr = reinterpret_cast<uintptr_t>(descriptorDisk->AccessFunctionPtr.get());
    auto typeMetadata = [self resolveMetadataFromCode:accessFuncPtr];
    const uint32_t *offsets = NULL;
    ivar *ivars = NULL;
    auto valid = payload::ValidDiskAddress((uintptr_t)typeMetadata);
    if (typeMetadata != nullptr && valid) {
        auto metadata = reinterpret_cast<TargetMetadata<InProcess> *>(typeMetadata);
        auto kind = metadata->getKind();
        
        if (kind == MetadataKind::Struct) {
            auto structMetadata = reinterpret_cast<StructMetadata*>(metadata);
            auto desc = const_cast<ValueTypeDescriptor*>(structMetadata->Description);
            auto descDisk = payload::CastToDisk<const StructDescriptor>(desc)->disk();
            if (descDisk->hasFieldOffsetVector()) {
                offsets = (uint32_t*)(descDisk->FieldOffsetVectorOffset + (uintptr_t*)metadata);
            }
            
        } else if (kind == MetadataKind::Class) {
            ivars = [self extractSwiftObjCIvars:descriptorDisk];
        } else if (kind == MetadataKind::Enum) {
            // TODO: ds
        }
    }
    
    auto numFields = fields->NumFields;
    if (xref_options.verbose >= VERBOSE_4 && numFields > 0) {
        printf("\n\n%s\t// Properties%s", dcolor(DSCOLOR_GRAY), color_end());
    }
    if (numFields) {
        putchar('\n');
    }
    if (!descriptorDisk->isReflectable()) {
        return;
    }

    ContextDescriptorKind kind = descriptorDisk->Flags.getKind();
    auto fieldRecords = descriptorDisk->Fields.get()->getFields();

    for (int i = 0; i < fieldRecords.size(); i++) {
        const char * declarationNameType;
        auto &pt = fieldRecords[i];
        declarationNameType = kind == ContextDescriptorKind::Enum ? "case" : pt.Flags.isVar() ? "var" : "let";
        auto mangledNameBase = makeSymbolicMangledNameStringRef(pt.MangledTypeName.get());
        
        // If resolved, don't need to demangle
        // https://github.com/DerekSelander/dsdump/issues/3
        bool resolved = false;
        StringRef mangledName = resolveExternalTypeDescriptorIfNeeded(mangledNameBase.data(), resolved);
        auto fieldName = pt.FieldName.get();
        std::string str;
        const char* resolvedSymbolicReference = resolved ? mangledName.data() : dshelpers::simple_type(mangledName, str);

        printf("\t%s%s %s %s %s%s", dcolor(DSCOLOR_GREEN),
                                           declarationNameType,
                                           fieldName,
                                           !mangledName.empty() ? ":" : "",
                                           resolvedSymbolicReference,
                                           color_end());
        if (xref_options.verbose >= VERBOSE_3 && (offsets || ivars)) {
            printf(" %s// +0x%x%s", dcolor(DSCOLOR_GRAY), ivars ? *ivars[i].offset->disk() : offsets[i], color_end());
            if (xref_options.verbose >= VERBOSE_4 && ivars) {
                printf(" %s(0x%x)%s", dcolor(DSCOLOR_GRAY), ivars[i].size, color_end());
            }
        }
        putchar('\n');
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


const char *getProtocolRequirementName(ProtocolRequirementFlags::Kind kind) {
    switch (kind) {
        case swift::ProtocolRequirementFlags::Kind::BaseProtocol:
            return "base protocol";
        case swift::ProtocolRequirementFlags::Kind::Method:
            return "method";
        case swift::ProtocolRequirementFlags::Kind::Init:
            return "init";
        case swift::ProtocolRequirementFlags::Kind::Getter:
            return "getter";
        case swift::ProtocolRequirementFlags::Kind::Setter:
            return "setter";
        case swift::ProtocolRequirementFlags::Kind::ReadCoroutine:
            return "read coroutine";
        case swift::ProtocolRequirementFlags::Kind::ModifyCoroutine:
            return "modify coroutine";
        case swift::ProtocolRequirementFlags::Kind::AssociatedTypeAccessFunction:
            return "associated type access function";
        case swift::ProtocolRequirementFlags::Kind::AssociatedConformanceAccessFunction:
            return "associated conformance access function";
            
    }
    return "unknown";
}

/// https://twitter.com/LOLgrep/status/1150820937773621248
const char * resolveExternalTypeDescriptorIfNeeded(const char *base, bool &resolved) {
  if (!base)
    return {};
    ContextDescriptor * contextDescriptor = nullptr;
    auto end = base;
    while (*end != '\0') {
        if (*end >= '\x01' && *end <= '\x17') {
            switch (*end++) {
                case '\x01':
                    contextDescriptor = (ContextDescriptor *)(*(int32_t *)(end) + (uintptr_t)end);
                    break;
                case '\x02':
                    contextDescriptor = payload::DiskWrapper<ContextDescriptor>::Cast(*(uintptr_t *)(*(int32_t *)end + (uintptr_t)end))->disk();
                    break;
            }
            break;

        } else if (*end >= '\x18' && *end <= '\x1F') {
            contextDescriptor = (ContextDescriptor *)++end;
            break;
        }
        ++end;
    }
    
    if (contextDescriptor) {
        resolved = true;
        switch (contextDescriptor->getKind()) {
            case ContextDescriptorKind::Enum:
                return reinterpret_cast<EnumDescriptor *>(contextDescriptor)->Name.get();
                break;
            case ContextDescriptorKind::Protocol:
                return reinterpret_cast<ProtocolDescriptor *>(contextDescriptor)->Name.get();
            case ContextDescriptorKind::Class:
                return reinterpret_cast<ClassDescriptor *>(contextDescriptor)->Name.get();
            case ContextDescriptorKind::Struct:
                return reinterpret_cast<StructDescriptor *>(contextDescriptor)->Name.get();
            default:
                resolved = false;
                break;
        }
    }
    
    return base;
}
