//
//  XRMachOLibrary+ObjectiveC.m
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+ObjectiveC.h"
#import "XRMachOLibrary+SymbolDumper.h"
#import <libgen.h>
#import "objc_.h"
#import "XRMachOLibrary+Swift.h"
#import <stddef.h>
#import "XRSymbolEntry.h"
//#import "Metadata.h"
//#import "MetadataValues.h"
//#import "Metadata.h"


typedef struct  {
    uint16_t mod_off : 16;
    uint16_t mod_len : 16;
    uint16_t cls_off : 16;
//    uint16_t cls_len : 10;
    BOOL success : 1;
} d_offsets;


// OffsetType used in
typedef enum {
    OffSetTypeIvar,
    OffSetTypeMethods,
    OffSetTypeProperties
} OffSetType;

// Swift uses offset references for ivars when referencing methods
static NSMutableDictionary *__ivarsDictionary = nil;

static NSDictionary <NSString*, NSNumber*> *blacklistedSelectors = nil;

@implementation XRMachOLibrary (ObjectiveC)

+ (void)load {
    blacklistedSelectors = @{
                             @".cxx_destruct" : @YES,
                             @"description" : @YES,
                             @"debugDescription" : @YES,
                             @"hash" : @YES
                             };
}

- (void)dumpObjCClassInfo:(const char *)name resolvedAddress:(uintptr_t)resolvedAddress {
    resolvedAddress = ARM64e_PTRMASK(resolvedAddress);
    uintptr_t methodsList_FO = [self offsetAddressForObjCClass:resolvedAddress forType:OffSetTypeMethods];  //[self methodsOffsetAddressForObjCClass:resolvedAddress];
    method_list_t *methodsList = NULL;
    int methodsCount = 0;
    class_ro_t *ro_info = NULL;
    
    uint8_t isMeta;
    if (methodsList_FO == FILE_OFFSET_UNKNOWN) {
        if (xref_options.debug) {
            dprintf(STDERR_FILENO, "%sCouldn't find method list! (%p)%s\n", dcolor(DSCOLOR_RED), (void*)resolvedAddress, color_end());
        }
        goto SWIFT_PART;
    }
    
    methodsList = (method_list_t *)DATABUF(methodsList_FO);
    methodsCount = methodsList->count;
    
    // Meta Needed to determine ObjC output class/instance type (-/+)
    ro_info = (class_ro_t *)DATABUF([self ROOffsetAddressForObjCClass:resolvedAddress]);
    isMeta = ro_info->flags & RO_META;
    
    for (int j = 0; j < methodsCount; j++) {
        
        
        uintptr_t methodOffset_FO = ARM64e_PTRMASK(*(uintptr_t *)(DATABUF(methodsList_FO + PTR_SIZE + (sizeof(method_t) * j))));
        uintptr_t methodOffset = [self translateLoadAddressToFileOffset:methodOffset_FO useFatOffset:YES];
        char *methodName = (char *)DATABUF(methodOffset);
        if (blacklistedSelectors[[NSString stringWithUTF8String:methodName]]) {
            continue;
        }
        putchar('\t');
        uintptr_t methodAddress = ARM64e_PTRMASK(*(uintptr_t *)(DATABUF(methodsList_FO + PTR_SIZE * 3 + (sizeof(method_t) * j))));
        printf("%s0x%011lx%s %s%c[%s %s]%s\n", dcolor(DSCOLOR_GRAY), methodAddress, color_end(), dcolor(DSCOLOR_BOLD), "-+"[isMeta], name, methodName, color_end());
    }
    
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
            printf("\t%s0x%011lx%s %s%s%s\n", dcolor(DSCOLOR_GRAY), (long)curSwiftMethod[i], color_end(), dcolor(DSCOLOR_CYANISH), entry.name, color_end());
        }
    }
}

/********************************************************************************
 // Properties
 ********************************************************************************/
- (void)dumpObjCPropertiesWithResolvedAddress:(uintptr_t)resolvedAddress {
    resolvedAddress = ARM64e_PTRMASK(resolvedAddress);
    intptr_t propertiesList_FO = [self offsetAddressForObjCClass:resolvedAddress forType:OffSetTypeProperties];
    
    if (propertiesList_FO == FILE_OFFSET_UNKNOWN) { return; }
    
    property_list_t *propertiesList = (property_list_t *)DATABUF(propertiesList_FO);
    propertiesList = (property_list_t *)ARM64e_PTRMASK((uintptr_t)propertiesList);
    
    uint32_t propertyCount = *(uint32_t *)DATABUF(propertiesList_FO + offsetof(property_list_t, count));
    property_t *properties = (property_t *)DATABUF(propertiesList_FO + offsetof(ivar_list_t, ivars));
    if (propertiesList_FO == FILE_OFFSET_UNKNOWN) {
        warn_debug("%sProperties not found! (%p)%s\n", dcolor(DSCOLOR_RED), resolvedAddress, color_end());
    }
    for (int i = 0; i < propertyCount; i++) {
        property_t property = properties[i];
        
        uintptr_t propertyName_FO = [self translateLoadAddressToFileOffset:(uintptr_t)property.name useFatOffset:YES];
        const char* propertyName = (const char *)DATABUF(propertyName_FO);
        
        uintptr_t propertyAttributes_FO = [self translateLoadAddressToFileOffset:(uintptr_t)property.attributes useFatOffset:YES];
        const char* propertyAttributes = (const char *)DATABUF(propertyAttributes_FO);
        
        printf("\t%s@property %s%s %s%s%s\n", dcolor(DSCOLOR_GREEN), propertyAttributes, color_end(), dcolor(DSCOLOR_BOLD), propertyName, color_end());
    }
}

/********************************************************************************
 // ivars
 ********************************************************************************/

- (void)dumpObjCInstanceVariablesWithResolvedAddress:(uintptr_t)resolvedAddress {
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

- (void)dumpObjectiveCClasses {
    // Defined symbols, will go after the __DATA.__objc_classlist pointers
    if (xref_options.defined || !(xref_options.undefined || xref_options.defined)) {
        
        struct section_64* class_list = (struct section_64* )[self.sectionCommandsDictionary[@"__DATA.__objc_classlist"]
                                         pointerValue];
        
        if (class_list) {
            uintptr_t offset = [self translateLoadAddressToFileOffset:class_list->addr useFatOffset:NO] + self.file_offset;
            uintptr_t *buff = (uintptr_t *)&self.data[offset];
            char modname[1024];
            for (int i = 0; i < class_list->size / PTR_SIZE; i++) {
                if (xref_options.swift_mode && ![self isSwiftClass:buff[i]]) {
                    continue;
                }
                
                uintptr_t resolvedAddress = ARM64e_PTRMASK(buff[i]);
                const char *name = [self nameForObjCClass:buff[i]];
                
                d_offsets off;
                if (xref_options.swift_mode && [self demangleSwiftName:name offset:&off]) {
                    strncpy(modname, &name[off.mod_off], off.mod_len);
                    modname[off.mod_len] = '\00';
                    printf("0x%011lx %s%s.%s%s", resolvedAddress,  dcolor(DSCOLOR_CYAN), modname, &name[off.cls_off], color_end());
                    
                } else {
                    printf("0x%011lx %s%s%s", resolvedAddress,  dcolor(DSCOLOR_CYAN), name, color_end());
                }
                
                XRBindSymbol *objcReference = nil;
                
                // Print out the superclass if any verbose level
                if (xref_options.verbose > VERBOSE_NONE) {
                    // Check if it's a local symbol first via the dylds binding opcodes....
                    objcReference = self.addressObjCDictionary[@((resolvedAddress + offsetof(ds_objc_class, superclass)))];
                    const char *supercls_name = objcReference.shortName.UTF8String;
                    
                    char *color = dcolor(DSCOLOR_GREEN);
                    if (!supercls_name) {
                        uintptr_t superClassAddress = ARM64e_PTRMASK(resolvedAddress + offsetof(ds_objc_class, superclass));
                        
                        offset = [self translateLoadAddressToFileOffset:superClassAddress useFatOffset:YES];
                        uintptr_t supercls = ARM64e_PTRMASK(*(uintptr_t *)&self.data[offset]);
                        
                        if (supercls) {
                            supercls_name = [self nameForObjCClass:supercls];
                            color = dcolor(DSCOLOR_MAGENTA);
                        }
                    }
                    color = supercls_name ? color : dcolor(DSCOLOR_RED);
                    if (xref_options.swift_mode && [self demangleSwiftName:supercls_name offset:&off]) {
                        strncpy(modname, &supercls_name[off.mod_off], off.mod_len);
                        modname[off.mod_len] = '\00';
                        printf(" : %s%s%s%s", color, modname, &supercls_name[off.cls_off], color_end());
                    } else {
                        class_ro_t *ro = (class_ro_t *)DATABUF([self ROOffsetAddressForObjCClass:buff[i]]);
                        if (!supercls_name && (ro->flags & RO_ROOT) == 0) {
                            printf(" %sbug! \"%s\" shouldn't be ROOT (report this to Derek) (0x%lu) %s", dcolor(DSCOLOR_RED), name,  resolvedAddress, color_end());
                        }
                        
                        printf(" : %s%s%s", color, supercls_name ? supercls_name : "<ROOT>", color_end());
                    }
                }
                
                // Print the libraries if verbose 4
                if (xref_options.verbose > VERBOSE_3) {
                    char *libName = objcReference && objcReference.libOrdinal ? (char*)self.depdencies[objcReference.libOrdinal].UTF8String : NULL;
                    if (libName) {
                        printf(" %s%s%s", dcolor(DSCOLOR_YELLOW), libName, color_end());
                    }
                }
                
                putchar('\n');
                // property then method dumping logic dumbing logic
                if (xref_options.verbose > VERBOSE_2) {
                    
                    intptr_t metacls_offset = [self translateLoadAddressToFileOffset:resolvedAddress useFatOffset:YES];
                    intptr_t resolvedMetaAddress = *(intptr_t *)DATABUF(metacls_offset);
                
                    // Dump properties...
                    [self dumpObjCInstanceVariablesWithResolvedAddress:resolvedAddress];
                    
                    [self dumpObjCPropertiesWithResolvedAddress:resolvedAddress];
                    
                    // Dumps class methods first...
                    [self dumpObjCClassInfo:name resolvedAddress:resolvedMetaAddress];
                    
                    // Then instance methods
                    [self dumpObjCClassInfo:name resolvedAddress:resolvedAddress];
                    
                    putchar('\n');
                    
                    swift_class *s = (swift_class *)resolvedAddress;
                    swift_class *meta = (swift_class *)resolvedMetaAddress;
                    
                    
//                    int32_t flags =  ResolveSwiftDescriptorAddress(s->description, flags);
//                    int32_t parent =  ResolveSwiftDescriptorAddress(s->description, parentOffset);
//                    intptr_t parentAddress = parent + (uintptr_t)&s->description->parentOffset;
//                    int32_t nameOffset = ResolveSwiftDescriptorAddress(s->description, namedOffset);
//                    char *name = (char *)(nameOffset + (uintptr_t)&s->description->namedOffset);
//
//                    int32_t property4Offset = ResolveSwiftDescriptorAddress(s->description, metadataAccessorOffset);
//                    uintptr_t property4 = (uintptr_t)(property4Offset + (uintptr_t)&s->description->metadataAccessorOffset);
                    char * name = (char*)TEST(s->description,    namedOffset);
                    uintptr_t fields = TEST(s->description,    fieldsOffset);
//                    uintptr_t reflection = TEST(s->description,    reflectionOffset);
//                    uintptr_t fieldOffset = TEST(s->description,    fieldsOffset);
                    
                    
                    
//                    printf("hmmm");
                }
            }
        }
    }
    
    // Undefined symbols, use the symbol table
    struct nlist_64 *symbols = self.symbols;
    if (xref_options.undefined || !(xref_options.undefined || xref_options.defined)) {
        for (int i = self.dysymtab->iundefsym; i < self.dysymtab->nundefsym + self.dysymtab->iundefsym; i++) {
            struct nlist_64 sym = symbols[i];
            char *chr = &self.str_symbols[sym.n_un.n_strx];
            
            if (!strnstr(chr, "_OBJC_CLASS_$_", OBJC_CLASS_LENGTH)) {
                continue;
            }
            //            NSString *name = [NSString stringWithUTF8String:chr];
            //            uintptr_t addr = self.stringObjCDictionary[name].address.unsignedLongValue;
            print_symbol(self, &sym, NULL);
        }
    }
}

-(const char *)nameForObjCClass:(uintptr_t)address {
    // Going after the class_ro_t of an ObjectiveC class
    // ommitting using Apple headers since their legal agreement is a PoS
    // On disk, class_ro_t seems to be stored at class_rw_t, so flip those around while on disk...
    
    
    address = ARM64e_PTRMASK(address);

    uintptr_t offset = [self translateLoadAddressToFileOffset:address useFatOffset:YES ];
    // Starts at __DATA.__objc_data, translate to file offset, going after class_rw_t 8
    if (!(offset )) {
        return NULL;
    }
    
    // Grab the  the class_rw_t data found in __DATA__objc_const, need to apply the FAST_DATA_MASK on the
    // class_data_bits_t since it can be not pointer aligned
    uintptr_t buff = ARM64e_PTRMASK(*(uintptr_t *)((uintptr_t)DATABUF(offset + (4 * PTR_SIZE)) & FAST_DATA_MASK));

    if (!(offset = [self translateLoadAddressToFileOffset:(buff & FAST_DATA_MASK) useFatOffset:YES])) {
        return NULL;
    }

    buff = ARM64e_PTRMASK(*(uintptr_t *)DATABUF(offset + (3 * PTR_SIZE)));
    if (!buff) {
        return NULL;
    }
    
    // transform it into file offset and deref...
    if (!(offset = [self translateLoadAddressToFileOffset:buff useFatOffset:YES])) {
        return NULL;
    }
    
    char *s = (char*)&self.data[offset];
    if (strlen(s)) {
        return s;
    }
    return NULL;
}

-(intptr_t)ROOffsetAddressForObjCClass:(uintptr_t)address {
    address = ARM64e_PTRMASK(address);
    intptr_t offset = [self translateLoadAddressToFileOffset:address useFatOffset:YES];
    // Starts at __DATA.__objc_data, translate to file offset, going after class_rw_t 8
    if (!(offset )) { return FILE_OFFSET_UNKNOWN; }
    
    // On disk, the bits value is gonna hold class_ro_t*  + other bit packing
    int disk_ro_offset = offsetof(ds_objc_class, bits);
    uintptr_t buff = ARM64e_PTRMASK(*(uintptr_t *)DATABUF(offset + disk_ro_offset));
    
    // buff now has the class_ro_t instance, translate to disk....
    if (!(offset = [self translateLoadAddressToFileOffset:(buff & FAST_DATA_MASK) useFatOffset:YES])) {
        return FILE_OFFSET_UNKNOWN;
    }
    return offset;
}

-(intptr_t)offsetAddressForObjCClass:(uintptr_t)address forType:(OffSetType)offsetType {
    
    intptr_t ro_offset = [self ROOffsetAddressForObjCClass:address];
    if (ro_offset == FILE_OFFSET_UNKNOWN) { return FILE_OFFSET_UNKNOWN; }
    
    int32_t offset;
    switch (offsetType) {
        case OffSetTypeIvar:
            offset = offsetof(class_ro_t, ivars);
            break;
        case OffSetTypeMethods:
            offset = offsetof(class_ro_t, baseMethodList);
            break;
        case OffSetTypeProperties:
            offset = offsetof(class_ro_t, baseProperties);
            break;
            
        default:
            assert(0);
            break;
    }
    uintptr_t buff = ARM64e_PTRMASK(*(uintptr_t *)DATABUF(ro_offset + offset));
    if (!buff) {
        return FILE_OFFSET_UNKNOWN;
    }
    
    // transform it into file offset and deref...
    if (!(ro_offset = [self translateLoadAddressToFileOffset:buff useFatOffset:YES])) {
        return FILE_OFFSET_UNKNOWN;
    }
    
    return ro_offset;
}

-(BOOL)isSwiftClass:(uintptr_t)address {
    uintptr_t offset = [self translateLoadAddressToFileOffset:address useFatOffset:NO ] + self.file_offset;
    if (!(offset)) {
        return NO;
    }
    
#define FAST_IS_SWIFT_LEGACY 1 // f'ing swift devs changing their minds every 3 seconds...
#define FAST_IS_SWIFT_STABLE 2
    uintptr_t buff = (*(uintptr_t *)DATABUF(offset +  offsetof(ds_objc_class, bits)));
    return buff & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE) ? YES : NO;
}

- (BOOL)demangleSwiftName:(const char *)name offset:(d_offsets *)f {

    return NO;
    [self loadSwiftDemangle];
//    const char * ff = [self demangledSwiftName:name];
//    "_TtC9SwiftTest14ViewController"
    if (!name || strlen(name) == 0) {
        f->success = NO;
        return NO;
    }
    if (!strnstr(name, "_TtC", 4)) {
        f->success = NO;
        return NO;
    }
    
    
    int index = strlen("_TtC");
    f->mod_off = index;
    while (name[index] >= '0' && name[index] <= '9') {
        index++;
    }
    char md_len[5] = {};
    strncpy(md_len, &name[f->mod_off], index - f->mod_off);
    f->mod_len = atoi(md_len);
    
    index += f->mod_len ;
    while (name[index] >= '0' && name[index] <= '9') {
        index++;
    }
    f->cls_off = index;
    f->mod_off++;
    return YES;
}

@end
