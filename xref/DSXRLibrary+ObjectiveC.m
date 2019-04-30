//
//  DSXRLibrary+ObjectiveC.m
//  xref
//
//  Created by Derek Selander on 4/29/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+ObjectiveC.h"
#import "DSXRLibrary+SymbolDumper.h"

#define FAST_DATA_MASK          0x00007ffffffffff8UL

@implementation DSXRLibrary (ObjectiveC)

- (void)dumpObjectiveCClasses {
    // Defined symbols, will go after the __DATA.__objc_classlist pointers
    if (xref_options.defined || !(xref_options.undefined || xref_options.defined)) {
        
        struct section_64* class_list = [self.sectionCommandsDictionary[@"__DATA.__objc_classlist"]
                                         pointerValue];
        if (class_list) {
            uintptr_t offset = [self translateLoadAddressToFileOffset:class_list->addr] + self.file_offset;
            uintptr_t *buff = calloc(1, class_list->size);
            pread(self.fd, buff, class_list->size, offset);
            
            for (int i = 0; i < class_list->size / PTR_SIZE; i++) {
                printf("0x%011lx %s%s%s", buff[i],  dcolor(DSCOLOR_CYAN), [self nameForObjCClass:buff[i]], colorEnd());
                
                
                if (xref_options.verbose) {
    
                    
                    // Check if it's an external symbol first via the dylds binding opcodes....
                    DSXRObjCClass *objcReference = self.addressObjCDictionary[@(buff[i] + PTR_SIZE)];
                    const char *name = objcReference.shortName.UTF8String;
                    
                    char *color = dcolor(DSCOLOR_GREEN);
                                        
                    if (!name) {
                        uintptr_t supercls;
                        pread(self.fd, &supercls, PTR_SIZE, [self translateLoadAddressToFileOffset:buff[i] + PTR_SIZE]);
                        if (supercls) {
                            name = [self nameForObjCClass:supercls];
                            color = dcolor(DSCOLOR_MAGENTA);
                        }
                    }
                    color = name ? color :  dcolor(DSCOLOR_RED);
                    printf(" : %s%s%s", color, name ? name : "<ROOT>", colorEnd());
                }
                
                putchar('\n');
            }
            
            free(buff);
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
            print_symbol(self, &sym);
        }
    }
}

-(const char *)nameForObjCClass:(uintptr_t)address {
    // Going after the class_ro_t of an ObjectiveC class
    // ommitting using Apple headers since their legal agreement is a PoS
    static char s[200];
    s[0] = '\00';
    
    uintptr_t offset;
    uintptr_t buff;
    if (!(offset = [self translateLoadAddressToFileOffset:address] + self.file_offset)) {
        return NULL;
    }
    pread(self.fd, &buff, PTR_SIZE, (offset + (4 * PTR_SIZE)));
    if (!buff) {
        return NULL;
    }
    if (!(offset = [self translateLoadAddressToFileOffset:(buff & FAST_DATA_MASK) + (3 * PTR_SIZE)] + self.file_offset)) {
        return NULL;
    }
    
    pread(self.fd, &buff, PTR_SIZE, offset);
    if (!buff) {
        return  NULL;
    }
    if (!(offset = [self translateLoadAddressToFileOffset:buff])) {
        return NULL;
    }
    
    pread(self.fd, s, 200, offset);
    if (strlen(s)) {
        return s;
    }
    return NULL;
}

@end
