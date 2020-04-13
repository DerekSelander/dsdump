//
//  XRMachOLibrary+SymbolDumper.m
//  xref
//
//  Created by Derek Selander on 4/22/19.
//  Copyright © 2019 Selander. All rights reserved.
//

#import "XRMachOLibrary+SymbolDumper.h"
#import "XRMachOLibrary+Opcode.h"
#import "XRMachOLibrary+ObjectiveC.h"
#import "XRSymbolEntry.h"
#import "XRMachOLibrary+Swift.h"
#import <libgen.h>
@implementation XRMachOLibrary (SymbolDumper)


- (void)dumpSymbols {
    

    if (xref_options.swift_mode && [self preparseSwiftTypes]) {
        [self preparseSwiftProtocols];
        [self dumpSwiftTypes];
    }
    
    if (xref_options.objectiveC_mode) {
        [self dumpObjectiveCClasses];
    }
    
    // If no mode  specified, defaults to nm
    if (xref_options.objectiveC_mode || xref_options.swift_mode) {
        return;
    }
    
    if (xref_options.debug) {
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
    
    if (!xref_options.symbol_mode) {
        return;
    }
    
    for (int i = 0; i < self.symtab->nsyms; i++) {
        struct nlist_64 symbol = self.symbols[i];
        
        // For stripped functions
        if ((xref_options.all_symbols || xref_options.analyze) && symbol.n_value && self.symbolEntry[@(symbol.n_value)]) {
            XRSymbolEntry *entry = self.symbolEntry[@(symbol.n_value)];
            entry.visited = true;
        }

        // If a debugging symbol only print if really verbose
        if ((symbol.n_type & N_STAB) && xref_options.verbose < VERBOSE_3) {
            continue;
        }
        
        if (xref_options.defined || xref_options.undefined) {
            if ((xref_options.defined && symbol.n_type & N_TYPE & N_SECT) || (xref_options.undefined && (symbol.n_type & N_TYPE) == N_UNDF)) {
                print_symbol(self, &self.symbols[i], NULL);
            }
        } else {
            print_symbol(self, &self.symbols[i], NULL);
        }
        
    }
    
    // Enumerate the stripped symbols if all_symbols is set
    if (xref_options.all_symbols) {
        for (NSNumber *key in self.symbolEntry) {
            XRSymbolEntry *entry = self.symbolEntry[key];
            if (entry.visited) { continue; }
            printf("0x%011llx %s<stripped>%s\n", entry.address, dcolor(DSCOLOR_RED), color_end());
        }
    }
}

- (void)dumpExternalSymbols {
    uintptr_t base = self.lazy_ptr_section->addr;
    size_t align_size = 1 << (self.lazy_ptr_section->align);
    const char *cyan = dcolor(DSCOLOR_CYAN);
    const char *end = color_end();
    const char *yellow = dcolor(DSCOLOR_YELLOW);
    
    for (int i = 0; i < self.indirect_symbols.count; i++) {
        int offset = self.indirect_symbols.indirect_sym[i];
        struct nlist_64 symbol = self.symbols[offset];
        int libIndex = GET_LIBRARY_ORDINAL(symbol.n_desc);
        char * chr = &self.str_symbols[symbol.n_un.n_strx];
        
        if (xref_options.verbose >= VERBOSE_1) {
            printf(" 0x%-8lx  %s%s%s: %s%-40s%s\n", base + (align_size * i), yellow, [self.depdencies[libIndex] UTF8String], end, cyan, chr, end);
        } else {
            printf(" 0x%-8lx  %s%-40s%s\n", base + (align_size * i), cyan, chr, end);
        }
    }
}

- (XRBindSymbol *)objCSuperClassFromSymbol:(struct nlist_64 * _Nonnull)sym {
    if (!(sym && sym->n_value)) {
        return nil;
    }
    
    XRBindSymbol *objcReference;
    uintptr_t buff = 0;
    uintptr_t fileOff = [self translateLoadAddressToFileOffset:sym->n_value + PTR_SIZE useFatOffset:NO];
    pread(self.fd, &buff, sizeof(void*), fileOff);
    
    // That buff is 0, then the class is defined elsewhere, use the opcode symbol bindings instead
    if (buff == 0) {
      objcReference = self.addressObjCDictionary[@(sym->n_value + PTR_SIZE)];
    } else {
        objcReference = self.addressObjCDictionary[@(buff)];
    }
    
    return objcReference;
}

@end


OS_ALWAYS_INLINE
void print_symbol(XRMachOLibrary *object, struct nlist_64 * _Nonnull sym, uintptr_t * _Nullable override_addr) {
    char * chr = &object.str_symbols[sym->n_un.n_strx];
    BOOL isObjC = NO;
    int output_len = 0;
    if (xref_options.objectiveC_mode && !strnstr(chr, "_OBJC_CLASS_$_", OBJC_CLASS_LENGTH)) {
        return;
    }
    output_len += printf("0x%011llx ", override_addr ? *override_addr : sym->n_value);
    if (xref_options.objectiveC_mode) {
        chr += OBJC_CLASS_LENGTH;
        isObjC = YES;
    }
    
    // nm -x option
    if (xref_options.verbose >= VERBOSE_3) {
        output_len += printf("%02x %02x %04x ", sym->n_type, sym->n_sect, sym->n_desc);
    }
    
    // Print the library path if verbose
    int libIndex = GET_LIBRARY_ORDINAL(sym->n_desc);
    if (xref_options.verbose >= VERBOSE_1) {
        if (sym->n_type & N_SECT && sym->n_sect) {
            struct section_64 * sec = (struct section_64 *)object.sectionCommandsArray[sym->n_sect].longValue;
            output_len += printf("%s%s.%s%s ", dcolor(DSCOLOR_GRAY), sec->segname, sec->sectname, color_end());
        } else if (libIndex > 0 && (sym->n_type & N_TYPE) == N_UNDF) {
            
            const char *libName;
            if (libIndex == DYNAMIC_LOOKUP_ORDINAL) {
                libName = "?????????";
            } else {
                libName = xref_options.verbose == 1 ? basename((char*)[object.depdencies[libIndex] UTF8String]) : [object.depdencies[libIndex] UTF8String];
            }
            output_len += printf("%s%s%s: ", dcolor(DSCOLOR_YELLOW), libName, color_end());
        }
    }
    
    // The actual symbol
    printf("%s%s%s ", dcolor(DSCOLOR_CYAN), chr, color_end());
    
    // If local ObjC class, print parent class
    if (isObjC && xref_options.objectiveC_mode && sym->n_value) {
        XRBindSymbol * objc_ref = [object objCSuperClassFromSymbol:sym];
        const char* superclassName =  [[objc_ref shortName] UTF8String];
        printf(": %s%s%s",dcolor(DSCOLOR_GREEN), superclassName?  superclassName : "<ROOT>", color_end());
    }
    
    putchar('\n');
}
