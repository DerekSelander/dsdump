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
#import <stddef.h>



typedef struct  {
    uint16_t mod_off : 16;
    uint16_t mod_len : 16;
    uint16_t cls_off : 16;
//    uint16_t cls_len : 10;
    BOOL success : 1;
} d_offsets;


@implementation XRMachOLibrary (ObjectiveC)

- (void)dumpObjCClassInfo:(const char *)name resolvedAddress:(uintptr_t)resolvedAddress {
    resolvedAddress = ARM64e_PTRMASK(resolvedAddress);
    intptr_t methodsStart = [self methodsOffsetAddressForObjCClass:resolvedAddress];
    if (methodsStart == METHODS_OFFSET_NONE) {
        return;
    }
    method_list_t *methods = (method_list_t *)DATABUF(methodsStart);
    int methodsCount = methods->count;
    
    class_ro_t *ro_info = (class_ro_t *)DATABUF([self ROOffsetAddressForObjCClass:resolvedAddress]);
    uint8_t isMeta = ro_info->flags & RO_META;
    for (int j = 0; j < methodsCount; j++) {
        
        
        uintptr_t methodName = ARM64e_PTRMASK(*(uintptr_t *)(DATABUF(methodsStart + PTR_SIZE + (sizeof(method_t) * j))));
        uintptr_t methodOffset = [self translateLoadAddressToFileOffset:methodName useFatOffset:YES];
        putchar('\t');

        
        uintptr_t methodAddress = (*(uintptr_t *)(DATABUF(methodsStart + PTR_SIZE * 3 + (sizeof(method_t) * j))));
        printf("%s0x%011lx%s %c[%s %s]\n", dcolor(DSCOLOR_GRAY), methodAddress, color_end(), "-+"[isMeta], name, DATABUF(methodOffset));
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
                
                XRBindSymbol *objcReference;
                
                if (xref_options.verbose > VERBOSE_NONE) {
                    // Check if it's a local symbol first via the dylds binding opcodes....
                    objcReference = self.addressObjCDictionary[@((resolvedAddress + PTR_SIZE))];
                    const char *supercls_name = objcReference.shortName.UTF8String;
                    
                    char *color = dcolor(DSCOLOR_GREEN);
                    
                    if (!supercls_name) {
                        uintptr_t superClassAddress = ARM64e_PTRMASK(resolvedAddress + PTR_SIZE);
                        
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
                        printf(" : %s%s%s", color, supercls_name ? supercls_name : "<ROOT>", color_end());
                    }
                }
                
                if (xref_options.verbose > VERBOSE_3) {
                    char *libName = objcReference && objcReference.libOrdinal ? (char*)self.depdencies[objcReference.libOrdinal].UTF8String : NULL;
                    if (libName) {
                        printf(" %s%s%s", dcolor(DSCOLOR_YELLOW), libName, color_end());
                    }
                }
                
                putchar('\n');
                if (xref_options.verbose > VERBOSE_2) {
                    
                    intptr_t metacls_offset = [self translateLoadAddressToFileOffset:resolvedAddress useFatOffset:YES];
                    intptr_t resolvedMeta = *(intptr_t *)DATABUF(metacls_offset);
                    [self dumpObjCClassInfo:name resolvedAddress:resolvedMeta];
                    
                    [self dumpObjCClassInfo:name resolvedAddress:resolvedAddress];
                    
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
    if (!(offset )) {
        return METHODS_OFFSET_NONE;
    }
    // Seems to be stored differently on disk than in memory, where the class_rw_t should reside...
    // Instead of the class_rw_t, the class_ro_t will be in the in memory spot, but here it's on disk
    int fake_rw_offset = offsetof(objc_class, bits);
    uintptr_t buff = ARM64e_PTRMASK(*(uintptr_t *)DATABUF(offset + fake_rw_offset - PTR_SIZE));
    // buff now has the class_ro_t instance, translate to disk....
    if (!(offset = [self translateLoadAddressToFileOffset:(buff & FAST_DATA_MASK) useFatOffset:YES])) {
        return METHODS_OFFSET_NONE;
    }
    return offset;
}

-(intptr_t)methodsOffsetAddressForObjCClass:(uintptr_t)address {

    intptr_t offset = [self ROOffsetAddressForObjCClass:address];
    if (offset == METHODS_OFFSET_NONE) { return METHODS_OFFSET_NONE; }
    
    uintptr_t buff = ARM64e_PTRMASK(*(uintptr_t *)DATABUF(offset + (4 * PTR_SIZE)));
    if (!buff) {
        return METHODS_OFFSET_NONE;
    }
    
    // transform it into file offset and deref...
    if (!(offset = [self translateLoadAddressToFileOffset:buff useFatOffset:YES])) {
        return METHODS_OFFSET_NONE;
    }
    
    return offset;
}


-(BOOL)isSwiftClass:(uintptr_t)address {

    uintptr_t offset = [self translateLoadAddressToFileOffset:address useFatOffset:NO ] + self.file_offset;
    if (!(offset)) {
        return NO;
    }
    
#define FAST_IS_SWIFT_LEGACY 1 // f'ing swift devs changing their minds every 3 seconds...
#define FAST_IS_SWIFT_STABLE 2
    
    uintptr_t buff = (*(uintptr_t *)DATABUF(offset + (4 * PTR_SIZE)));
    
    return buff & (FAST_IS_SWIFT_LEGACY|FAST_IS_SWIFT_STABLE) ? YES : NO;
}

- (BOOL)demangleSwiftName:(const char *)name offset:(d_offsets *)f {

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
