//
//  DSXRLibrary+SymbolDumper.m
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "DSXRLibrary+SymbolDumper.h"
#import "DSXRLibrary+Opcode.h"
@implementation DSXRLibrary (SymbolDumper)



/********************************************************************************
 // Dump symbols
 ********************************************************************************/

- (void)dumpSymbols {
    
  
    if (xref_options.verbose >= 4 ) {
        struct dysymtab_command * d = self.dysymtab;
        printf("\
               ilocalsym: %d, nlocalsym: %d\n\
               iextdefsym: %d, nextdefsym: %d\n\
               iundefsym: %d, nundefsym: %d\n\
               modtaboff: %d, nmodtab: %d\n\
               extrefsymoff: %d, nextrefsyms: %d\n\
               indirectsymoff: %d, nindirectsyms: %d\n\
               extreloff: %d, nextrel: %d\n\
               locreloff: %d, nlocrel: %d\n", d->ilocalsym, d->nlocalsym, d->iextdefsym, d->nextdefsym, d->iundefsym, d->nundefsym, d->modtaboff, d->nmodtab, d->extrefsymoff, d->nextrefsyms, d->indirectsymoff, d->nindirectsyms, d->extrefsymoff, d->nextrel, d->locreloff, d->nlocrel);
    }
    for (int i = 0; i < self.symtab->nsyms; i++) {
        
        struct nlist_64 symbol = self.symbols[i];
        
        
        // if stripped
        if (!symbol.n_un.n_strx && xref_options.verbose < 4)  { continue; }
        
        
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        

        
        // If not a valid symbol
        if (strlen(chr) < 2 && xref_options.verbose < 4) {
            continue;
        }
        
        // If a debugging symbol only print if really verbose
        if ((symbol.n_type & N_STAB) && xref_options.verbose < 3) {
            continue;
        }
        
//        // objc tmp stuff
//        if (!strnstr(chr, "_OBJC_CLASS_$_", 14) || !symbol.n_value ) {
//            continue;
//        }
        
//        [self addToDictionaries:symbol.n_value symbol:chr];
        
        
        if (xref_options.verbose > 2 && !xref_options.objc_only) {
            printf("(%d) ", i);
        }

        if (xref_options.defined || xref_options.undefined) {
            if ((xref_options.defined && symbol.n_type & N_TYPE & N_SECT) || (xref_options.undefined && (symbol.n_type & N_TYPE) == N_UNDF)) {
                [self printSymbol:&self.symbols[i]];
            }
        } else {
            [self printSymbol:&self.symbols[i]];
        }
        
    }
    
//    [self dumpObjectiveCSymbols];
}

//- (void)dumpObjectiveCSymbols {
//   struct section_64 *sec = [self.sectionCommandsDictionary[@"__DATA.__objc_classlist"] pointerValue];
//    
//    int count = sec->size / sizeof(void*);
////    printf("counldt si %d\n", sec->size);
//    uintptr_t addr = sec->addr;
//    
//    uintptr_t *ptrs = calloc(1, sec->size);
//    pread(self.fd, ptrs, sec->size, self.file_offset + sec->offset);
////
////    for (int i = 0; i < count; i++, addr += sizeof(void*)) {
//////        self.addressDictionary[@(]
////
////        sec->offset
////    }
//    
//    for (int i = 0; i < sec->size / sizeof(void*); i++) {
//        printf("%p %s : %s\n", ptrs[i], [[self.addressObjCDictionary[@(ptrs[i])] shortName] UTF8String
//                                         ], [[self.addressObjCDictionary[@(ptrs[i] + 8)] shortName] UTF8String]);
//    }
//}


- (void)dumpExternalSymbols {
    uintptr_t base = self.lazy_ptr_section->addr;
    size_t align_size = 1 << (self.lazy_ptr_section->align);
    for (int i = 0; i < self.indirect_symbols.count; i++) {
        int offset = self.indirect_symbols.indirect_sym[i];
        struct nlist_64 symbol = self.symbols[offset];
        int libIndex = GET_LIBRARY_ORDINAL(symbol.n_desc);
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        
        if (xref_options.verbose) {
            printf(" 0x%-8lx  %s%s%s: %s%-40s%s\n", base + (align_size * i), dcolor(DSCOLOR_YELLOW), [self.depdencies[libIndex] UTF8String], colorEnd(), dcolor(DSCOLOR_CYAN), chr, colorEnd() );
        } else {
            printf(" 0x%-8lx  %s%-40s%s\n", base + (align_size * i), dcolor(DSCOLOR_CYAN), chr, colorEnd() );
        }
    }
}


- (void)printSymbol:(struct nlist_64 *)sym {
    char * chr = &self.str_symbols[sym->n_un.n_strx];
    // If not a valid symbol
    if (strlen(chr) < 2) {
        chr = "<stripped symbol>";
    }
    
    if (xref_options.objc_only && !strnstr(chr, "_OBJC_CLASS_$_", 14)) {
        return;
    }
    BOOL isObjC = NO;
    if (xref_options.objc_only) {
        chr += 14;
        isObjC = YES;
    }
    
    int output_len = 0;
    
    output_len += printf("0x%011llx ", sym->n_value);
    
    if (xref_options.verbose >= 2) {
        output_len += printf("%02x %02x %04x ", sym->n_type, sym->n_sect, sym->n_desc);
    }
    
    int libIndex = GET_LIBRARY_ORDINAL(sym->n_desc);
    if (xref_options.verbose >= 1) {
        if (sym->n_type & N_SECT && sym->n_sect) {
            struct section_64 * sec = ( struct section_64 * )self.sectionCommandsArray[sym->n_sect].longValue;
            output_len += printf("%s%s.%s%s ", dcolor(DSCOLOR_GRAY), sec->segname, sec->sectname, colorEnd());
        } else if (libIndex > 0 && (sym->n_type & N_TYPE) == N_UNDF) {
            const char *libName = [self.depdencies[libIndex] UTF8String];
            output_len += printf("%s%s%s: ", dcolor(DSCOLOR_YELLOW), libName, colorEnd());
        }
    }
    printf("%s%s%s ", dcolor(DSCOLOR_CYAN), chr, colorEnd());
    if (isObjC && xref_options.objc_only && sym->n_value) {
        
        uintptr_t fileOff = [self loadAddressToFileOffset:sym->n_value + sizeof(void*)];
        uintptr_t buff;
        pread(self.fd, &buff, 8, fileOff + self.file_offset);
        
        // That buff is 0, then the class is defined elsewhere, use the opcode symbol bindings instead
        DSXRObjCClass *objcReference;
        if (buff == 0) {
            objcReference = self.addressObjCDictionary[@(sym->n_value + sizeof(void*))];
        } else {
            objcReference = self.addressObjCDictionary[@(buff)];
        }
        
        printf(": %s%s%s",dcolor(DSCOLOR_MAGENTA), [objcReference.shortName UTF8String], colorEnd());
    }
    putchar('\n');
}

@end
