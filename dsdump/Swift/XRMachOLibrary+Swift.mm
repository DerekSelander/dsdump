//
//  XRMachOLibrary+Swift.m
//  xref
//
//  Created by Derek Selander on 5/18/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import <dlfcn.h>
#import "XRMachOLibrary+Swift.h"
#import "XRSymbolEntry.h"
#import "objc_.h"
#import "XRMachOLibrary+ObjectiveC.h"
#import "string.h"
#import <unordered_map>
#import <iostream>
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
const char *getKindMethodString(swift::MethodDescriptorFlags::Kind kind);
static char *demangledName(const char* mangledTypeName);

using namespace std;
using namespace swift;


int testShit () {return 4;}

static NSMutableDictionary * __ivarsDictionary = nil;


// Used to sort all the type references by module
using DescriptorDict =  unordered_map<const TargetModuleContextDescriptor<InProcess>*, std::vector<TypeContextDescriptor*>>;
static DescriptorDict moduleDescriptorDictionary;

unordered_map<const ModuleContextDescriptor *, std::vector<ProtocolDescriptor*>> moduleProtocolDictionary;

// Fast lookup from swift type which lists all the supported protocols
static unordered_map<const ContextDescriptor*, std::vector<const ProtocolDescriptor*>> swiftProtocolsToTypesDictionary;

/**
 Swift Type Descriptors currently don't give enough deets about the methods, so using objc, to get that missing info
 This will associate the type descriptor with the corresponding class found in the ObjC classes (__objc_classlist)
 */
static unordered_map<TargetClassDescriptor<InProcess>*, swift_class*> swiftDescriptorToClassDictionary;

char *GetProtocolFlagsDescription(ProtocolRequirementFlags *req) {
    switch (req->getKind()) {
        case ProtocolRequirementFlags::Kind::BaseProtocol:
            
            break;
            
        default:
            break;
    }
    return NULL;
    
}

//ProtocolRequirementFlags

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
    
    int32_t *ztypeOffsets = (int32_t*)swiftTypes->addr;
    auto typeOffsets = payload::DiskWrapper<int32_t>::Cast(swiftTypes->addr);

    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        auto resolvedTypedOffset = (intptr_t)typeOffsets[i].disk() + *typeOffsets[i].disk();
        auto descriptor = reinterpret_cast<TypeContextDescriptor *>(resolvedTypedOffset);
        
        
        
        int32_t ztypeOffset = TODISKDEREF(&ztypeOffsets[i]);
        uintptr_t zresolvedTypedOffset = (uintptr_t)(&ztypeOffsets[i]) + ztypeOffset;
        TypeContextDescriptor* zdescriptor = TODISK(reinterpret_cast<TypeContextDescriptor*>(zresolvedTypedOffset));
        
        assert(zdescriptor == descriptor);
        auto module = descriptor->getModuleContext();
        
        const TargetModuleContextDescriptor<InProcess> * zmodule = zdescriptor->getModuleContext();
        if (module == nullptr) {
            continue;
        }
        assert(module == zmodule);
        
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

        auto swiftClassDiskPointer = classes[i]->load()->disk();
        if (!(swiftClassDiskPointer->bits & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE))) {
            continue;
        }
        
        auto &swiftClassDisk  = *swiftClassDiskPointer;
        auto descriptor = swiftClassDisk->descriptor->disk();
        swiftDescriptorToClassDictionary[descriptor] = classes[i]->load();
        
    }

    return YES;
}

- (void)dumpSwiftProtocols {
    struct section_64* swiftTypes = payload::sectionsDict["__TEXT.__swift5_protos"];
    if (!swiftTypes) {
        if (payload::sectionsDict["__TEXT.__swift4_protos"]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
    }
    
    auto protoOffsets = payload::DiskWrapper<int32_t>::Cast(swiftTypes->addr);
    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        auto resolvedTypedOffset = (intptr_t)protoOffsets[i].disk() + *protoOffsets[i].disk();
        auto protocol = reinterpret_cast<ProtocolDescriptor *>(resolvedTypedOffset);
        auto requirements = protocol->getRequirements();
        for (auto __unused &req : requirements) {

#warning implement me hopefully by Swift 5.2?
            // TODO: https://github.com/apple/swift/blob/659c49766be5e5cfa850713f43acc4a86f347fd8/include/swift/ABI/Metadata.h#L1717
        }
    }
//    [self preparseSwiftProtocols];
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
    
    auto protoOffsets = payload::DiskWrapper<int32_t>::Cast(swiftTypes->addr);
    for (int i = 0; i < swiftTypes->size / sizeof(int32_t); i++) {
        
        auto resolvedTypedOffset = (uintptr_t)((intptr_t)(protoOffsets[i].disk()) + *protoOffsets[i].disk());
        auto protocolConformance = reinterpret_cast<ProtocolConformanceDescriptor *>(resolvedTypedOffset);
        auto typeDescriptor = protocolConformance->getTypeDescriptor();
        auto protocol = protocolConformance->getProtocol();
        auto recast = static_cast<const ContextDescriptor*>(typeDescriptor);
        swiftProtocolsToTypesDictionary.emplace(recast, std::vector<const ProtocolDescriptor*>());
        swiftProtocolsToTypesDictionary.at(recast).push_back(protocol);
        
    }
    
    return;
}

- (void)dumpProtocolsForTypeContextDescriptor:(TypeContextDescriptor*)descriptor {
    auto found = swiftProtocolsToTypesDictionary.find(descriptor);
    if (found == swiftProtocolsToTypesDictionary.end()) { return; }
    putchar(',');
    auto supportedProtocols = found->second;
    auto count = supportedProtocols.size();
    for (int i = 0; i< count; i++) {
        auto protocol = supportedProtocols[i];
        printf(" %s", protocol->Name.get());
        if (i != count - 1) {
            putchar(',');
            putchar(' ');
        }
    }
}

- (void)dumpSwiftTypes {
    
    // Iterate all Swift descriptors in swift5_types
    for (auto ptr = moduleDescriptorDictionary.begin(); ptr != moduleDescriptorDictionary.end(); ++ptr ) {
        
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
                    
                    auto structDescriptor = static_cast<TargetStructDescriptor<InProcess> *>(descriptor);
                    putchar(' ');
                    putchar('{');
                    [self dumpTargetTypeContextDescriptorFields:structDescriptor];
                    
                    break;
                } case ContextDescriptorKind::Class: {
                    auto classDescriptorDisk = static_cast<TargetClassDescriptor<InProcess> *>(descriptor);
                    classDescriptorDisk->Parent.get();
                    
                    classDescriptorDisk->getTypeContextDescriptorFlags();
                    auto it = swiftDescriptorToClassDictionary.find(classDescriptorDisk);
                    if (it == swiftDescriptorToClassDictionary.end()) { continue; }
                    auto swiftClassLoad = it->second; // Load
                    auto &swiftClassDisk = *swiftClassLoad->disk(); // Disk

                    DSCOLOR color;
                    const char *demangledName = NULL;
                    auto superclass_ptr = swiftClassDisk->superclass;
                    std::string outDemangledstring;
            
                    // Print out parent
#warning ARM64e tmp hack
                    if (reinterpret_cast<uintptr_t>(superclass_ptr) & 0x0000000FFFFFFFF0UL) {
                        auto &superclass = *superclass_ptr; // Needed fo the overloaded -> operator
                        auto &rodata = *superclass->rodata();
                        auto mangledName = rodata->name->disk();
                        dshelpers::simple_demangle(mangledName, outDemangledstring);
                        demangledName = outDemangledstring.c_str();
                        color = DSCOLOR_MAGENTA;
                    } else {
                        XRBindSymbol *bindSymbol = self.addressObjCDictionary[@((uintptr_t)&swiftClassLoad->superclass)];
                        auto name = bindSymbol.name.UTF8String;
                        if (name && strnstr(name, "_OBJC_CLASS_$_", strlen("_OBJC_CLASS_$_"))) {
                            name = &name[strlen("_OBJC_CLASS_$_")];
                        }
                        dshelpers::simple_demangle(name, outDemangledstring);
                        demangledName = outDemangledstring.c_str();
                        color = DSCOLOR_GREEN;
                    }

                    printf(" : %s%s%s", dcolor(color), demangledName, color_end());
                    [self dumpProtocolsForTypeContextDescriptor:descriptor];
                    
                    putchar(' ');
                    putchar('{');

                    [self dumpTargetTypeContextDescriptorFields:classDescriptorDisk];
                    
                    // Methods
                    [self dumpSwiftMethods:classDescriptorDisk];
                    break;
                    
                } case ContextDescriptorKind::Protocol:
                    NSLog(@"yoyoyo");
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
    
    putchar('\n');
}


- (void)dumpSwiftMethods:(TargetClassDescriptor<InProcess>*)classDescriptor {
    
    auto methodDescriptors = classDescriptor->getMethodDescriptors();
    if (xref_options.verbose >= VERBOSE_4 && methodDescriptors.size()) {
        printf("\n%s\t// Swift methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
    }
    
    auto it = swiftDescriptorToClassDictionary.find(classDescriptor);
    if (it == swiftDescriptorToClassDictionary.end()) {
        return;
    }
    
    auto swiftClassLoad = it->second;
    char stripped[PATH_MAX];
    snprintf(stripped, PATH_MAX, "%s%s%s", dcolor(DSCOLOR_RED), "<stripped>", color_end());
    
    for (auto &pt : methodDescriptors) {
        if (pt.Impl.isNull()) {
            continue;
        }
     
        auto flags = pt.Flags;
        auto methodAddress = reinterpret_cast<uintptr_t>(FROMDISK(pt.Impl.get()));
        auto entry = self.symbolEntry[@(methodAddress)];
        
        std::string outDemangledString;
        dshelpers::simple_demangle(entry.name, outDemangledString);
        
    
        bool isInstanceMethod = pt.Flags.isInstance();

        
        
        const char *resolvedMethodName = outDemangledString.length() == 0 ? stripped : outDemangledString.c_str();
        printf("\t%s%p%s%s %s func %s%s", dcolor(DSCOLOR_GRAY), methodAddress, color_end(), dcolor(DSCOLOR_BOLD), isInstanceMethod ? "" : " class", resolvedMethodName, color_end());
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
        if (kind ==  ContextDescriptorKind::Enum) {
            declarationNameType = "case";
        } else {
            declarationNameType = pt.Flags.isVar() ? "var" : "let";
        }

        auto mangledTypeName = pt.MangledTypeName.get();
        auto fieldName = pt.FieldName.get();

//        auto mangledName = pt.getMangledTypeName(0);
        const char* resolvedSymbolicReference = "";
        
        if (mangledTypeName) {
            // Check if a symbolic reference (visible in properties that reference classes in same module)
            if (mangledTypeName[0] >= '\x01' && mangledTypeName[0] <= '\x17') {
                
                int32_t symbolReference = *(int32_t*)&mangledTypeName[1];
                auto resolvedTypeDescriptor = (uintptr_t)&mangledTypeName[1] + (uintptr_t)symbolReference;
                
                payload::LoadToDiskTranslator<TypeContextDescriptor>* resolvedDescriptor = reinterpret_cast<payload::LoadToDiskTranslator<TypeContextDescriptor> *>(resolvedTypeDescriptor);
                resolvedSymbolicReference = resolvedDescriptor->disk()->Name.get();

            } else {
                std::string str;
                resolvedSymbolicReference = dshelpers::simple_type(mangledTypeName, str);
            }
        }
        
        printf("\t%s%s %s %s %s%s\n", dcolor(DSCOLOR_GREEN),
                                           declarationNameType,
                                           fieldName,
                                           mangledTypeName ? ":" : "",
                                           resolvedSymbolicReference,
                                           //mangledName[0] & '\x01' ? resolvedSymbolicReference : demangledName,
                                           color_end());
 
        
    }
    
    putchar('\n');
}

- (void)dumpSwiftInstanceVariablesWithResolvedAddress:(uintptr_t)resolvedAddress {
    resolvedAddress = ARM64e_PTRMASK(resolvedAddress);
    intptr_t ivarList_FO = [self offsetAddressForObjCClass:resolvedAddress forType:OffSetTypeIvar];
    
    ivar_list_t *ivarList = (ivar_list_t *)DATABUF(ivarList_FO);
    ivarList = (ivar_list_t *)ARM64e_PTRMASK((uintptr_t)ivarList);
    
    
    uint32_t ivarCount = *(uint32_t *)DATABUF(ivarList_FO + offsetof(ivar_list_t, count));
    
     __ivarsDictionary = [NSMutableDictionary dictionaryWithCapacity:ivarCount];
    ivar_t *ivars = (ivar_t *)DATABUF(ivarList_FO + offsetof(ivar_list_t, ivars));
    if (ivarCount && ivarList_FO != FILE_OFFSET_UNKNOWN) {
        putchar('{');
        putchar('\n');
    }
    for (int i = 0; ivarList_FO != FILE_OFFSET_UNKNOWN && i < ivarCount; i++) {
        ivar_t ivar = ivars[i];
        uintptr_t ivarOffset_FO = [self translateLoadAddressToFileOffset:(uintptr_t)ivar.offset useFatOffset:YES];
        uint32_t ivarOffset = *(uint32_t*)DATABUF(ivarOffset_FO);
        
        uintptr_t ivarName_FO = [self translateLoadAddressToFileOffset:(uintptr_t)ivar.name useFatOffset:YES];
        char* ivarName = (char *)DATABUF(ivarName_FO);
        
        __ivarsDictionary[@(ivarOffset)] = [NSString stringWithUTF8String:ivarName];
        printf("\t+0x%04x %s (0x%x)\n", ivarOffset, ivarName, ivar.size);
    }
    
    if (ivarCount && ivarList_FO != FILE_OFFSET_UNKNOWN) {
        putchar('}');
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
