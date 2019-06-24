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
using DescriptorDict =  unordered_map<const TargetModuleContextDescriptor<InProcess>*, vector<TypeContextDescriptor*>>;
static DescriptorDict moduleDescriptorDictionary;

/**
 Swift Type Descriptors currently don't give enough deets about the methods, so using objc, to get that missing info
 This will associate the type descriptor with the corresponding class found in the ObjC classes (__objc_classlist)
 */
unordered_map<TargetClassDescriptor<InProcess>*, swift_class*> swiftDescriptorToClassDictionary;

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
    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
    if (!swiftTypes) {
        if ([self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return NO;
    }
    
    int32_t *typeOffsets = (int32_t*)swiftTypes->addr;
    for (int i = 0; i < swiftTypes->size / sizeof(uint32_t); i++) {
        int32_t typeOffset = TODISKDEREF(&typeOffsets[i]);
        uintptr_t resolvedTypedOffset = (uintptr_t)(&typeOffsets[i]) + typeOffset;
        TypeContextDescriptor* descriptor = TODISK(reinterpret_cast<TypeContextDescriptor*>(resolvedTypedOffset));
        const TargetModuleContextDescriptor<InProcess> * module = descriptor->getModuleContext();
        moduleDescriptorDictionary.emplace(module, vector<TypeContextDescriptor*>());
        moduleDescriptorDictionary.at(module).push_back(descriptor);
    }
    
    ///////////////////////
    // swiftDescriptorToClassDictionary logic
    //////////////////////////
    struct section_64* class_list = (struct section_64* )[self.sectionCommandsDictionary[@"__DATA.__objc_classlist"] pointerValue];
    if (!class_list) { class_list = (struct section_64* )[self.sectionCommandsDictionary[@"__DATA_CONST.__objc_classlist"] pointerValue]; }
    if (!class_list) {
        perror("Couldn't find __objc_classlist segment?!\n");
        return YES;
    }

    swift_class **classes = TODISK(reinterpret_cast<swift_class**>(class_list->addr));
    int numClasses = class_list->size / PTR_SIZE;
  
#define FAST_IS_SWIFT_LEGACY 1 // f'ing swift devs changing their minds every 3 seconds...
#define FAST_IS_SWIFT_STABLE 2
    
    for (int i = 0; i < numClasses; i++) {
        auto swiftClass = TODISK(classes[i]);
        if (!(swiftClass->bits & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE))) {
            continue;
        }
        // classes[i] will be the load address,
        swiftDescriptorToClassDictionary[TODISK(swiftClass->description)] = classes[i];
    }
    
    return YES;
}



/*
 
 SWIFT_PART:
 if (xref_options.swift_mode && [self isSwiftClass:resolvedAddress]) {
 uintptr_t classSizeOffset_FO = [self translateLoadAddressToFileOffset:resolvedAddress + offsetof(swift_class, classSize) useFatOffset:YES];
 uint32_t classSize = *(uint32_t *)DATABUF(classSizeOffset_FO);
 uintptr_t classAddressOffset_FO = [self translateLoadAddressToFileOffset:(resolvedAddress + offsetof(struct swift_class_t, classAddressOffset)) useFatOffset:YES];
 uint32_t classAddressOffset = *(uint32_t *)DATABUF(classAddressOffset_FO);
 
 
 uintptr_t description_FO = [self translateLoadAddressToFileOffset:(resolvedAddress + offsetof(struct swift_class_t, swiftMethods)) useFatOffset:YES];
 uintptr_t *curSwiftMethod = (uintptr_t *)DATABUF(description_FO);
 
 int swiftMethodCount = (classSize - classAddressOffset - offsetof(struct swift_class_t, swiftMethods)) / PTR_SIZE;
 for (int i = 1; i < swiftMethodCount; i++) {
 //            if (!curSwiftMethod[i]) { continue; }
 XRSymbolEntry *entry = self.symbolEntry[@(curSwiftMethod[i])];
 NSString *resolvedSwiftProperty = __ivarsDictionary[@(curSwiftMethod[i])];
 if (!entry.name && resolvedSwiftProperty) {
 continue;
 }
 std::string str;
 printf("\t%s0x%011lx%s %s%s%s\n", dcolor(DSCOLOR_GRAY), (long)curSwiftMethod[i], color_end(), dcolor(DSCOLOR_CYANISH), dshelpers::simple_demangle(entry.name, str), color_end());
 }
 }

 */

- (void)dumpSwiftTypes {
    
    struct section_64* swiftTypes = (struct section_64*)[self.sectionCommandsDictionary[@"__TEXT.__swift5_types"] pointerValue];
    if (!swiftTypes) {
        if ([self.sectionCommandsDictionary[@"__TEXT.__swift4_types"] pointerValue]) {
            printf("%sdsdump only supports swift5 :[\n%s", dcolor(DSCOLOR_RED), color_end());
        }
        return;
    }
    

    for ( auto ptr = moduleDescriptorDictionary.begin(); ptr != moduleDescriptorDictionary.end(); ++ptr ) {
        
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
                    [self dumpTargetTypeContextDescriptorFields:structDescriptor];
                    
                    break;
                } case ContextDescriptorKind::Class: {
                    auto classDescriptor = static_cast<TargetClassDescriptor<InProcess> *>(descriptor);

                    auto it = swiftDescriptorToClassDictionary.find(classDescriptor);
                    if (it == swiftDescriptorToClassDictionary.end()) { continue; }
                    auto swiftClassLoad = it->second; // Load
                    auto &swiftClassDisk = *swiftClassLoad->disk(); // Disk
                    
                    
//                    auto &a = *swiftClassDisk;
//                    auto g = payload::AddressTranslator<swift_class*>(swiftClassLoad);
                 
//                    g->classSize
//                    g->rodata();
                    
//                    (*swiftClassLoad)->operator->()->superclass;
//                    auto gg = a->superclass;
//                    swiftClassDisk->sup
                    
//                    a->superclass;
//                    printf("da fuck\n");
//                    swiftClassLoad
//                    swiftClassLoad->()
                    
//                    auto swiftClassDisk = swiftClassLoad->diskGet();
//
//
//                    auto ee = swiftClassDisk->wrap();
//
////                    auto ee = swiftClassLoad
//                    ++swiftClassDisk;
//                    swiftClassDisk++;
//                    ++ee;
//                    ee++;
//                    auto iis = ee + 5;
////                    +ee;
////                    auto gg = swiftClassDisk->rodata();
////                    auto gh = swiftClassDisk->reserved;
////                    swiftClassLoad
////                    auto name = swiftClassLoad->diskGet()->rodata->diskGet()->name.disk()->unwrap();
//                    std::string str;
                    DSCOLOR color;
////                    auto mangledName = swiftClassLoad->diskGet()->rodata()->unwrap()->name;
                    const char *demangledName = NULL;
                    // Print out parent
                    
                    auto superclass_ptr = swiftClassDisk->superclass;
                    std::string outDemangledstring;
                    
                    if (superclass_ptr) {
                        auto &superclass = *superclass_ptr; // Needed fo the overloaded -> operator
                        auto &rodata = *superclass->rodata();
                        auto mangledName = rodata->name->disk();
                        dshelpers::simple_demangle(mangledName, outDemangledstring);
                        demangledName = outDemangledstring.c_str();
                        color = DSCOLOR_MAGENTA;
                    } else {
                        XRBindSymbol *bindSymbol = self.addressObjCDictionary[@((uintptr_t)&swiftClassLoad->superclass)];
                        auto name = bindSymbol.name.UTF8String;
                        if (strnstr(name, "_OBJC_CLASS_$_", strlen("_OBJC_CLASS_$_"))) {
                            name = &name[strlen("_OBJC_CLASS_$_")];
                        }
                        dshelpers::simple_demangle(name, outDemangledstring);
                        demangledName = outDemangledstring.c_str();
                        color = DSCOLOR_GREEN;
                    }

                    printf(" : %s%s%s \n", dcolor(color), demangledName, color_end());
                    putchar(' ');
                    putchar('{');
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
    
    putchar('\n');
}


- (void)dumpSwiftMethods:(TargetClassDescriptor<InProcess>*)classDescriptor {
    
    auto methodDescriptors = classDescriptor->getMethodDescriptors();
    if (xref_options.verbose >= VERBOSE_4 && methodDescriptors.size()) {
        printf("\n%s\t// Swift methods%s\n", dcolor(DSCOLOR_GRAY), color_end());
    }
//    auto swiftDescriptorToClassDictionary.find(classDescriptor);
    
    auto it = swiftDescriptorToClassDictionary.find(classDescriptor);
    if (it == swiftDescriptorToClassDictionary.end()) {
        return;
    }
    
    auto swiftClassLoad = it->second;
//    auto swiftClass_disk = TODISK(swiftClass_load);
//    auto rodata_disk = TODISK(swiftClass_disk->rodata());
//    auto objcMethods = rodata_disk->baseMethodList;

//    swiftClass_disk->classAddressOffset /
    
    
//    swiftClass_disk->
    
//    uintptr_t classSizeOffset_FO = [self translateLoadAddressToFileOffset:resolvedAddress + offsetof(swift_class, classSize) useFatOffset:YES];
//    uint32_t classSize = *(uint32_t *)DATABUF(classSizeOffset_FO);
//    uintptr_t classAddressOffset_FO = [self translateLoadAddressToFileOffset:(resolvedAddress + offsetof(struct swift_class_t, classAddressOffset)) useFatOffset:YES];
//    uint32_t classAddressOffset = *(uint32_t *)DATABUF(classAddressOffset_FO);
//
//
//    uintptr_t description_FO = [self translateLoadAddressToFileOffset:(resolvedAddress + offsetof(struct swift_class_t, swiftMethods)) useFatOffset:YES];
//    uintptr_t *curSwiftMethod = (uintptr_t *)DATABUF(description_FO);
//
//    int swiftMethodCount = (classSize - classAddressOffset - offsetof(struct swift_class_t, swiftMethods)) / PTR_SIZE;
//    for (int i = 1; i < swiftMethodCount; i++) {
//        //            if (!curSwiftMethod[i]) { continue; }
//        XRSymbolEntry *entry = self.symbolEntry[@(curSwiftMethod[i])];
//        NSString *resolvedSwiftProperty = __ivarsDictionary[@(curSwiftMethod[i])];
//        if (!entry.name && resolvedSwiftProperty) {
//            continue;
//        }
//        std::string str;
//        printf("\t%s0x%011lx%s %s%s%s\n", dcolor(DSCOLOR_GRAY), (long)curSwiftMethod[i], color_end(), dcolor(DSCOLOR_CYANISH), dshelpers::simple_demangle(entry.name, str), color_end());
//    }
//    }
    
    
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
        
        
        bool isInstance = pt.Flags.isInstance();

        
        
        const char *resolvedMethodName = outDemangledString.length() == 0 ? stripped : outDemangledString.c_str();
        printf("\t%s%p%s%s %s func %s%s", dcolor(DSCOLOR_GRAY), methodAddress, color_end(), dcolor(DSCOLOR_BOLD), isInstance ? "" : " class", resolvedMethodName, color_end());
        if (xref_options.verbose >= VERBOSE_3) {
            printf(" %s// %s %s", dcolor(DSCOLOR_GRAY), getKindMethodString(flags.getKind()), color_end());
        }
        
        putchar('\n');
    }
}

/// AKA properties
- (void)dumpTargetTypeContextDescriptorFields:(TypeContextDescriptor*)contextDescriptor {
    auto fields = contextDescriptor->Fields.get();
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
    if (!contextDescriptor->isReflectable()) {
        return;
    }

    ContextDescriptorKind kind = contextDescriptor->Flags.getKind();
    auto fieldRecords = contextDescriptor->Fields.get()->getFields();

    
    auto contextDescriptor_load = FROMDISK(contextDescriptor);

    for (auto &pt : fieldRecords) {
        
        const char * declarationNameType;
        if (kind ==  ContextDescriptorKind::Enum) {
            declarationNameType = "case";
        } else {
            declarationNameType = pt.Flags.isVar() ? "var" : "let";
        }

        auto mangledTypeName = (pt.MangledTypeName.get());
        auto fieldName = (pt.FieldName.get());

        
        std::string str;
        const char* demangledName = dshelpers::simple_type(mangledTypeName, str);
        
        printf("\t%s%s %s %s %s %s\n", dcolor(DSCOLOR_GREEN), declarationNameType, fieldName, mangledTypeName ? ":" : "", mangledTypeName? demangledName : "", color_end());
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
